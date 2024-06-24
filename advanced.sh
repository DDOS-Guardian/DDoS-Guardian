#!/bin/bash


sudo apt-get update
sudo apt-get install -y iptables-persistent fail2ban unbound

iptables -F
iptables -X


iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --set
iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --update --seconds 300 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT




iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j DROP

iptables -A INPUT -p tcp -m multiport --dports 80,8080,443,2022 -j ACCEPT


iptables -A INPUT -p tcp -m limit --limit 25/minute --limit-burst 100 -m multiport --dports 80,8080 -j ACCEPT
iptables -A INPUT -p tcp -m limit --limit 25/minute --limit-burst 100 -m multiport --dports 443,2022 -j ACCEPT


iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 --connlimit-mask 32 --connlimit-saddr -j DROP

iptables -A INPUT -i pterodactyl0 -j ACCEPT
iptables -A FORWARD -o pterodactyl0 -j ACCEPT
iptables -A FORWARD -i pterodactyl0 -j ACCEPT
iptables -A INPUT -i docker0 -j ACCEPT
iptables -A FORWARD -o docker0 -j ACCEPT
iptables -A FORWARD -i docker0 -j ACCEPT



iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT


iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -j ACCEPT


iptables -A INPUT -p tcp --dport 2375 -j ACCEPT
iptables -A INPUT -p tcp --dport 2376 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT


iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP


iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP


iptables -t mangle -A PREROUTING -p icmp -j DROP


iptables -t mangle -A PREROUTING -f -j DROP


iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset


iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP


iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP


iptables -A INPUT -p udp --dport 53 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT


iptables -A INPUT -m conntrack --ctstate INVALID -j DROP


iptables -N HEAVY_TRAFFIC
iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j HEAVY_TRAFFIC
iptables -A HEAVY_TRAFFIC -j LOG --log-prefix "Heavy Traffic: " --log-level 7
iptables -A HEAVY_TRAFFIC -j DNAT --to-destination 109.71.253.231


iptables -A INPUT -p tcp -m limit --limit 100/sec --limit-burst 200 -j ACCEPT
iptables -A INPUT -p udp -m limit --limit 100/sec --limit-burst 200 -j ACCEPT


iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT


iptables-save > /etc/iptables/rules.v4



sudo systemctl enable netfilter-persistent


sudo apt-get install -y fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log

[http-get-dos]
enabled = true
port = http,https
filter = http-get-dos
logpath = /var/log/apache2/access.log
maxretry = 300
findtime = 300
bantime = 600
EOF

cat <<EOF > /etc/fail2ban/filter.d/http-get-dos.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

sudo systemctl restart fail2ban


sudo apt-get install -y unbound
cat <<EOF > /etc/unbound/unbound.conf
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    verbosity: 1
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 2

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
EOF


sudo systemctl restart unbound
sudo systemctl enable unbound
systemctl restart docker

echo "Firewall has been organized and is now enabled, powered by DDOS Guardian."
