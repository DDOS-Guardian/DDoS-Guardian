#!/bin/bash

# Initial system update and package installation
sudo apt-get update
sudo apt-get install -y iptables-persistent fail2ban unbound

# Flush existing iptables rules
iptables -F
iptables -X

# Accept all traffic from whitelisted IP to bypass further checks
iptables -A INPUT -s 109.71.253.231 -j ACCEPT

# Basic rules for loopback and established connections
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH connection rate limiting to protect against brute-force attacks
iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --set
iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --update --seconds 300 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# General rules for accepting HTTP(S) and other specified traffic
iptables -A INPUT -p tcp -m multiport --dports 80,8080,443,2022 -j ACCEPT

# Detect heavy traffic and redirect it
iptables -N SUSPICIOUS_TRAFFIC
iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j SUSPICIOUS_TRAFFIC
iptables -A SUSPICIOUS_TRAFFIC -j LOG --log-prefix "Suspicious Traffic: " --log-level 7
iptables -A SUSPICIOUS_TRAFFIC -j DNAT --to-destination 109.71.253.231

# Allow and log all new incoming traffic, monitoring for heavy loads
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j LOG --log-prefix "New Connection: " --log-level 7

# Accept DNS traffic
iptables -A INPUT -p udp --dport 53 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Default policy: accept all other traffic
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Save the iptables configuration
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
