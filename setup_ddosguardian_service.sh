#!/bin/bash

if [ -d "/etc/ddos-guardian" ]; then
    echo "Directory /etc/ddos-guardian is already installed..."
    exit 1
fi

confirm_installation() {
    local answer
    read -p "Are you sure you want to install DDoS Guardian? (yes/no): " answer </dev/tty
    answer=${answer:-no}  # Default to "no" if no input is provided
    if [ "$answer" = "yes" ]; then
        echo "Installing DDoS Guardian..."
        install_ddos_guardian
    else
        echo "Installation canceled."
        exit 1
    fi
}

install_ddos_guardian() {
    
    cd /etc/
    
    apt update
    
    git clone https://github.com/xlelord9292/ddos-guardian .
    curl -Lo ddos-guardian.tar.gz https://github.com/DDOS-Guardian/DDoS-Guardian/releases/latest/download/ddos-guardian.tar.gz
    tar -xzvf ddos-guardian.tar.gz
    rm ddos-guardian.tar.gz
    
    if ! command -v node &> /dev/null; then
        curl -sL https://deb.nodesource.com/setup_14.x | bash -
        apt install -y nodejs
    fi
    
    npm install
    
    cat <<EOF > /etc/systemd/system/guardian.service
    [Unit]
    Description=DDoS Guardian Service
    After=network.target
    
    [Service]
    Type=simple
    User=root
    WorkingDirectory=/etc/ddos-guardian
    ExecStart=/usr/bin/node /etc/ddos-guardian/attacks.js
    Restart=always
    StandardOutput=syslog
    StandardError=syslog
    
    [Install]
    WantedBy=multi-user.target
    EOF
    
    systemctl daemon-reload
    
    systemctl enable guardian
    systemctl start guardian
    
    
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p udp -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -j DROP
    
    iptables -A INPUT -i lo -j ACCEPT
    
    
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    
    
    iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT
    
    iptables -A INPUT -j LOG --log-prefix "Dropped: "
    
    
    iptables -A INPUT -j DROP
    
    
    iptables-save > /etc/iptables/rules.v4
    
    
    cd /etc/nginx/conf.d/
    git clone https://github.com/xlelord9292/ddos-guardian-layer-7
    
    sudo apt-get install libnginx-mod-http-lua
    
    echo "DDoS Guardian setup complete."
}

confirm_installation
