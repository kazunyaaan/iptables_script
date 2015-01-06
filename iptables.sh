#!/bin/bash

# For debug
if true; then
  if [ "${EUID:-${UID}}" = "0" ]; then
    echo '---- Debug mode ----'
    echo 'user権限で実行してください'
    exit 1
  fi
  shopt -s expand_aliases
  alias iptables='echo iptables'
fi

create_logchain ()
{
  local chain=$1
  local jump=$2

  local mode=$3
  local limit=$4
  local burst=$5
  local expire=$6

  local logopt="$7"
  local log_tag=${chain%_LOG}

  iptables -N $chain
  iptables -A $chain \
    -m hashlimit --hashlimit-name $chain --hashlimit-mode $mode --hashlimit $limit --hashlimit-burst $burst --hashlimit-htable-expire $expire \
    -j LOG --log-level info --log-prefix "IPTABLES[$log_tag]:" $logopt
  iptables -A $chain -j $jump
}


WAN_IP=XXX.XXX.XXX.XXX
WAN_NET=XXX.XXX.XXX.XXX/XX
WAN_BCAST=XXX.XXX.XXX.255
WAN_IF=eth0

LAN_IP=192.168.1.1
LAN_NET=192.168.1.0/24
LAN_BCAST=192.168.1.255
LAN_IF=eth1

DMZ_IP=172.31.1.1
DMZ_NET=172.31.1.0/24
DMZ_BCAST=172.31.1.255
DMZ_IF=eth2



# webサーバー(DMZ内)
DMZ_HTTP_SERVER_IP=172.31.1.XX
DMZ_HTTP_SERVER_MAC=XX:XX:XX:XX:XX:XX


# IP,MACホワイトリスト(LAN,DMZ)
WHITE_LOCAL_MAC_ADDR=(
  $DMZ_HTTP_SERVER_MAC
)
WHITE_LOCAL_IP_ADDR=(
  $DMZ_HTTP_SERVER_IP
)

# DHCP用LAN側MAC
WHITE_LAN_MAC_ADDR=()


####
# 初期化
####

# ポリシー
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# 全テーブル初期化
iptables -t filter -F
iptables -t nat -F
iptables -t mangle -F

# 全ユーザー定義チェイン削除
iptables -t filter -X
iptables -t nat -X
iptables -t mangle -X

# 全カウンタリセット
iptables -t filter -Z
iptables -t nat -Z
iptables -t mangle -Z


####
# ループバックを許可
####

iptables -A INPUT -i lo -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT


####
# パスMTU問題対処
####
# ref: http://centossrv.com/linux-router.shtml
# ref: http://linuxjf.sourceforge.jp/JFdocs/Adv-Routing-HOWTO/lartc.cookbook.mtu-mss.html

iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu


####
# 異常なTCPコネクションの検出
####
# ref: http://www.asahi-net.or.jp/~aa4t-nngk/ipttut/output/newnotsyn.html

# NEWステートなのにSYNでないtcp
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP


####
# ingress filter (WAN)
####
# ref: https://www.nic.ad.jp/ja/basics/terms/ingress-filtering.html

create_logchain INGRESS_LOG DROP srcip 1/m 3 180000

# ingress in (WAN側から入ってくるプライベートIPに偽装したパケットを破棄)
iptables -N INGRESS_IN
iptables -A INGRESS_IN -s 10.0.0.0/8 -j INGRESS_LOG
iptables -A INGRESS_IN -s 172.16.0.0/12 -j INGRESS_LOG
iptables -A INGRESS_IN -s 192.168.0.0/16 -j INGRESS_LOG
iptables -A INPUT -i $WAN_IF -j INGRESS_IN

# ingress out (WAN側から何故か出ようとするプライベートIP宛のパケットを破棄)
iptables -N INGRESS_OUT
iptables -A INGRESS_OUT -d 10.0.0.0/8 -j DROP
iptables -A INGRESS_OUT -d 172.16.0.0/12 -j DROP
iptables -A INGRESS_OUT -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -o $WAN_IF -j INGRESS_OUT

# ingress forward
iptables -N INGRESS_FWD
iptables -A INGRESS_FWD -i $WAN_IF -s 10.0.0.0/8 -j INGRESS_LOG
iptables -A INGRESS_FWD -o $WAN_IF -d 10.0.0.0/8 -j INGRESS_LOG
iptables -A INGRESS_FWD -i $WAN_IF -s 172.16.0.0/12 -j INGRESS_LOG
iptables -A INGRESS_FWD -o $WAN_IF -d 172.16.0.0/12 -j INGRESS_LOG
iptables -A INGRESS_FWD -i $WAN_IF -s 192.168.0.0/16 -j INGRESS_LOG
iptables -A INGRESS_FWD -o $WAN_IF -d 192.168.0.0/16 -j INGRESS_LOG
iptables -A FORWARD -j INGRESS_FWD


####
# DHCP (udp:67,68)
####
# ref: http://network.station.ez-net.jp/os/linux/daemon/dhcp/iptables/centos/5.5.asp
# 通信はLAN側のみ許可する（DMZは拒否）
# (接続元IPおよび接続先IPは指定しない代わりに、interfaceでLAN側を指定)

# LAN側からDHCP許可
iptables -A INPUT -i $LAN_IF -p udp --sport 68 --dport 67 -j ACCEPT # request


#####
# I/O IP check (LAN, DMZ)
#####
# 各interfaceから出入りするIPをチェックする。
# INPUT,OUTPUTだけチェックする(FORWARDはここではチェックしない)

create_logchain INV_IP_IN_LOG DROP srcip 1/m 3 180000

# LAN
iptables -A INPUT -i $LAN_IF ! -s $LAN_NET -j INV_IP_IN_LOG
iptables -A OUTPUT -o $LAN_IF ! -d $LAN_NET -j DROP

# DMZ
iptables -A INPUT -i $DMZ_IF ! -s $DMZ_NET -j INV_IP_IN_LOG
iptables -A OUTPUT -o $DMZ_IF ! -d $DMZ_NET -j DROP


####
# パケット転送のIPアドレス,MACアドレスフィルタリング
####

create_logchain UN_IP_MAC_LOG DROP srcip 5/m 5 180000

# IP,MAC組み合わせチェック
iptables -N CHECK_IP_MAC
for (( i = 0; i < ${#WHITE_LOCAL_MAC_ADDR[@]}; i++ ))
do
  iptables -A CHECK_IP_MAC -s ${WHITE_LOCAL_IP_ADDR[$i]} -m mac --mac-source ${WHITE_LOCAL_MAC_ADDR[$i]} -j RETURN
done
iptables -A CHECK_IP_MAC -j UN_IP_MAC_LOG	# 未知のIPアドレスとMACアドレスの組み合わせは破棄

# LAN,DMZのみチェック対象
iptables -A FORWARD -i $LAN_IF -j CHECK_IP_MAC
iptables -A FORWARD -i $DMZ_IF -j CHECK_IP_MAC


####
# 確立済みの通信を許可
####

# all
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# tcp,icmp
iptables -A FORWARD -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT


####
# 各種攻撃対策など
####
# ref: http://centossrv.com/linux-router.shtml
# ref: http://qiita.com/suin/items/5c4e21fa284497782f71
# ref: http://www.popolog.net/articles/2011/04/iptables_shell_analysis.html


# フラグメントパケットの破棄
#（フラグメントパケットを使った攻撃を防ぐ。
# iptables単体では攻撃用と正規のフラグメントパケットを適切に切り分けられないため、フラグメントパケットは全て拒否する）
# 攻撃の種類の参考: http://esupport.trendmicro.com/solution/ja-jp/1305068.aspx
create_logchain FRAGMENT_LOG DROP srcip 1/m 3 180000
iptables -A INPUT -f -j FRAGMENT_LOG
iptables -A FORWARD -f -j FRAGMENT_LOG
iptables -A OUTPUT -f -j FRAGMENT_LOG


# ステルススキャンらしきパケットを破棄
create_logchain ST_SCAN_LOG DROP srcip 1/m 3 180000 --log-tcp-options
iptables -N CHECK_STEALTH_SCAN
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ACK,FIN FIN -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ACK,PSH PSH -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ACK,URG URG -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags FIN,RST FIN,RST -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags SYN,RST SYN,RST -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ALL ALL -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ALL NONE -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j ST_SCAN_LOG
iptables -A CHECK_STEALTH_SCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j ST_SCAN_LOG
iptables -A INPUT -p tcp -j CHECK_STEALTH_SCAN
iptables -A OUTPUT -p tcp -j CHECK_STEALTH_SCAN
iptables -A FORWARD -p tcp -j CHECK_STEALTH_SCAN


# シーケンスナンバー予測攻撃防止(DROPしちゃだめ)
# ref: http://www.asahi-net.or.jp/~aa4t-nngk/ipttut/output/synackandnew.html
create_logchain SEQ_ATTACK_LOG REJECT srcip 1/m 3 180000 --log-tcp-options
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j SEQ_ATTACK_LOG
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j SEQ_ATTACK_LOG
iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j SEQ_ATTACK_LOG


# ICMP処理
iptables -N ICMP_TYPE_CHECK
# ping許可(ping of death対策として84バイト以下のパケットのみ許可)
# ref: http://oxynotes.com/?p=6401
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type echo-request -m length --length :85 -j RETURN
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type echo-reply -m length --length :85 -j RETURN
# その他いくつかの必須ICMPを許可
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type destination-unreachable -j RETURN
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type source-quench -j RETURN
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type time-exceeded -j RETURN
iptables -A ICMP_TYPE_CHECK -p icmp --icmp-type parameter-problem -j RETURN
iptables -A ICMP_TYPE_CHECK -j DROP	# それ以外拒否
create_logchain ICMP_LIMIT_LOG DROP srcip 1/m 3 180000
iptables -N ICMP_LIMIT
iptables -A ICMP_LIMIT -j ICMP_TYPE_CHECK
# ICMPの通信数に制限をかける(flood対策)
iptables -A ICMP_LIMIT \
  -m hashlimit --hashlimit-name ICMP_LIMIT --hashlimit-mode srcip --hashlimit 10/s --hashlimit-burst 30 --hashlimit-htable-expire 300000 \
  -j ACCEPT
iptables -A ICMP_LIMIT -j ICMP_LIMIT_LOG  # 通信数の制限越えたものはログとって破棄
iptables -A INPUT -p icmp -j ICMP_LIMIT
iptables -A FORWARD -p icmp -j ICMP_LIMIT
iptables -A OUTPUT -p icmp -j ICMP_LIMIT


# SYN Cookiesを有効化(TCP SYN flood攻撃対策)
# ref: http://ja.wikipedia.org/wiki/SYN_cookies
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >>/etc/sysctl.conf


# ブロードキャストアドレス宛pingには応答しない（Smurf攻撃対策）
# ref: http://e-words.jp/w/SmurfE694BBE69283.html
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >>/etc/sysctl.conf


# ICMP Redirectパケットは拒否(ICMPリダイレクトによるルーティング変更を拒否)
# ref: http://www.atmarkit.co.jp/fwin2k/win2ktips/613icmpredir/icmpredir.html
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
  sysctl -w net.ipv4.conf.$dev.accept_redirects=0 >/dev/null
  echo "net.ipv4.conf.$dev.accept_redirects=0" >>/etc/sysctl.conf
done


# Source Routedパケットは拒否(IP Source Routing Attack対策)
# ref: http://software.fujitsu.com/jp/manual/manualfiles/M060001/J2S19680/01Z2A/sff02/sff00068.html
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
  sysctl -w net.ipv4.conf.$dev.accept_source_route=0 >/dev/null
  echo "net.ipv4.conf.$dev.accept_source_route=0" >>/etc/sysctl.conf
done


# 全ホスト宛のマルチキャストアドレスは破棄
iptables -A INPUT -d 224.0.0.1 -j DROP
iptables -A FORWARD -d 224.0.0.1 -j DROP


# ブロードキャストアドレスは破棄
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d $WAN_BCAST -j DROP
iptables -A INPUT -d $LAN_BCAST -j DROP
iptables -A INPUT -d $DMZ_BCAST -j DROP
iptables -A FORWARD -d 255.255.255.255 -j DROP
iptables -A FORWARD -d $WAN_BCAST -j DROP
iptables -A FORWARD -d $LAN_BCAST -j DROP
iptables -A FORWARD -d $DMZ_BCAST -j DROP


#####
# NetBIOS関係のパケットをLANから出さない
#####
# ref: http://centossrv.com/linux-router.shtml

iptables -A INPUT -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A INPUT -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A OUTPUT -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP
iptables -A OUTPUT -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP
iptables -A FORWARD -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A FORWARD -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A FORWARD -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP
iptables -A FORWARD -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP


####
# IDENT (tcp:113)
####
# ref: http://centossrv.com/linux-router.shtml
# 破棄せず拒否（メールサーバーなどのレスポンス低下防止のため）

iptables -A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --dport 113 -j REJECT --reject-with tcp-reset


#####
# DNS (udp:53)
#####
# 問い合わせはLAN,DMZからのみ許可する（WANからは許可しない）

# LAN,DMZ側から許可
iptables -A INPUT -i $LAN_IF -p udp --dport 53 -j ACCEPT	# request
iptables -A INPUT -i $DMZ_IF -p udp --dport 53 -j ACCEPT	# request


####
# NTP (udp:123)
####
# 問い合わせはLAN,DMZからのみ許可する（WANからは許可しない）

# LAN側から許可
iptables -A INPUT -i $LAN_IF -p udp --dport 123 -j ACCEPT	# request
iptables -A INPUT -i $DMZ_IF -p udp --dport 123 -j ACCEPT	# request


####
# SSH (tcp:22)
####
# (SSHサーバー)全NIC、全接続元から許可（個別のIPフィルタリングは/etc/hosts.allow,hosts.denyで制御する）
iptables -A INPUT -p tcp -m state --state NEW --dport 22 \
  -m hashlimit --hashlimit-burst 5 --hashlimit 1/m --hashlimit-mode srcip --hashlimit-htable-expire 300000 --hashlimit-name SSH_LIMIT \
  -j ACCEPT


####
# IPマスカレード (LAN,DMZのみ)
####
iptables -t nat -A POSTROUTING -s $LAN_NET -o $WAN_IF -j MASQUERADE
iptables -t nat -A POSTROUTING -s $DMZ_NET -o $WAN_IF -j MASQUERADE


####
# ステートNEWのパケット転送の記録用LOGチェイン
####

iptables -N FWD_NEW_ACCEPT_LOG
iptables -A FWD_NEW_ACCEPT_LOG -m state --state NEW -j LOG --log-level info --log-prefix "IPT[FWD_NEW_ACCEPT]:"
iptables -A FWD_NEW_ACCEPT_LOG -j ACCEPT


#####
# HTTP (tcp:80)
#####
# tcp:80をDMZ内のwebサーバー($DMZ_HTTP_SERVER_IP)のtcp:80に転送する

# 全NIC、全接続元から許可し、webサーバーへパケット転送（個別のIPフィルタリングはwebサーバー側で設定）
iptables -t nat -A PREROUTING -d $WAN_IP -p tcp --dport 80 --sport 1024: -j DNAT --to-destination $DMZ_HTTP_SERVER_IP	# DMZ内のwebサーバーへ
iptables -t nat -A OUTPUT -d $WAN_IP -p tcp --dport 80 --sport 1024: -j DNAT --to-destination $DMZ_HTTP_SERVER_IP	# (Gateway自身からwebサーバーへ)
iptables -A FORWARD -i $DMZ_IF -s $DMZ_HTTP_SERVER_IP -d $WAN_IP -p tcp --dport 80 -j REJECT --reject-with icmp-port-unreachable	# webサーバーからのtcp:80への接続は転送許可しない(ループする可能性があるため)
iptables -A FORWARD -o $DMZ_IF -p tcp --dport 80 --sport 1024: -d $DMZ_HTTP_SERVER_IP -j FWD_NEW_ACCEPT_LOG	# 転送許可





####
# その他パケット転送許可(tcp,icmpのみ)
####

# to WAN
iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p icmp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $DMZ_IF -o $WAN_IF -p tcp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $DMZ_IF -o $WAN_IF -p icmp -j FWD_NEW_ACCEPT_LOG

# to DMZ
iptables -A FORWARD -i $LAN_IF -o $DMZ_IF -p tcp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $LAN_IF -o $DMZ_IF -p icmp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $WAN_IF -o $DMZ_IF -p tcp -j FWD_NEW_ACCEPT_LOG
iptables -A FORWARD -i $WAN_IF -o $DMZ_IF -p icmp -j FWD_NEW_ACCEPT_LOG





####
# iptables-save
####
cp /etc/sysconfig/iptables /etc/sysconfig/iptables.backup
iptables-save >/etc/sysconfig/iptables
