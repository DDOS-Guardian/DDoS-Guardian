const express = require('express');
const httpProxy = require('http-proxy');
const fs = require('fs');
const net = require('net');
const dgram = require('dgram');
const http = require('http');

const MAX_CONNECTIONS_PER_IP = 100;
const CONNECTION_TIMEOUT = 60000;
const BLACKLIST_TIMEOUT = 300000;
const MAX_REQUESTS_PER_MINUTE = 100;
const LOG_FILE = 'logs.txt';

const connections = {};
const blacklist = {};
const requestCounts = {};
const loggedIPs = new Set();

function addToBlacklist(ip) {
    console.log(`Blacklisting IP address: ${ip}`);
    blacklist[ip] = true;
    setTimeout(() => {
        console.log(`Removing IP address from blacklist: ${ip}`);
        delete blacklist[ip];
        loggedIPs.delete(ip);  // Remove IP from logged set when removed from blacklist
    }, BLACKLIST_TIMEOUT);
}

function logDDoSAttack(ip, pps, port) {
    const logLine = `DDoS Attack Detected: IP ${ip} | Packets per second: ${pps} | Port: ${port}\n`;
    fs.appendFile(LOG_FILE, logLine, (err) => {
        if (err) {
            console.error('Error writing to logs file:', err);
        } else {
            loggedIPs.add(ip);
        }
    });
}

function handleIncomingData(socket, remoteAddress, remotePort) {
    let packetCount = 0;
    let pps = 0;
    const interval = setInterval(() => {
        pps = packetCount;
        packetCount = 0;
    }, 1000);

    socket.on('data', data => {
        packetCount++;
        console.log(`Received data from ${remoteAddress}:${remotePort} - ${data}`);
    });

    socket.on('end', () => {
        clearInterval(interval);
        connections[remoteAddress]--;
        console.log(`Connection closed with ${remoteAddress}:${remotePort}`);
    });

    socket.on('error', err => {
        clearInterval(interval);
        console.error(`Error with connection from ${remoteAddress}:${remotePort} - ${err.message}`);
        connections[remoteAddress]--;
        socket.destroy();
    });

    setInterval(() => {
        if (pps > MAX_CONNECTIONS_PER_IP) {
            console.log(`DDoS attack detected from ${remoteAddress}:${remotePort}. Packets per second: ${pps}`);
            if (!loggedIPs.has(remoteAddress)) {
                logDDoSAttack(remoteAddress, pps, remotePort);
            }
            addToBlacklist(remoteAddress);
            clearInterval(interval);
            socket.destroy();
        }
    }, 1000);
}

function applyFirewallRules(socket, remoteAddress, remotePort) {
    if (blacklist[remoteAddress]) {
        console.log(`Rejected connection from blacklisted IP: ${remoteAddress}`);
        socket.destroy();
        return;
    }
    connections[remoteAddress] = (connections[remoteAddress] || 0) + 1;
    socket.setTimeout(CONNECTION_TIMEOUT, () => {
        connections[remoteAddress]--;
        console.log(`Connection timeout for ${remoteAddress}:${remotePort}`);
    });
    handleIncomingData(socket, remoteAddress, remotePort);
}

const tcpServer = net.createServer(socket => {
    const remoteAddress = socket.remoteAddress;
    const remotePort = socket.remotePort;
    console.log(`Incoming TCP connection from ${remoteAddress}:${remotePort}`);
    applyFirewallRules(socket, remoteAddress, remotePort);
});

const udpServer = dgram.createSocket('udp4');
udpServer.on('error', (err) => {
    console.error(`UDP server error:\n${err.stack}`);
    udpServer.close();
});

const udpConnections = {};

udpServer.on('message', (msg, rinfo) => {
    const remoteAddress = rinfo.address;
    const remotePort = rinfo.port;
    console.log(`Incoming UDP message from ${remoteAddress}:${remotePort}`);
    if (!udpConnections[remoteAddress]) {
        udpConnections[remoteAddress] = { count: 0, interval: null };
        udpConnections[remoteAddress].interval = setInterval(() => {
            const pps = udpConnections[remoteAddress].count;
            udpConnections[remoteAddress].count = 0;
            if (pps > MAX_CONNECTIONS_PER_IP) {
                console.log(`DDoS attack detected from ${remoteAddress}:${remotePort}. Packets per second: ${pps}`);
                if (!loggedIPs.has(remoteAddress)) {
                    logDDoSAttack(remoteAddress, pps, remotePort);
                }
                addToBlacklist(remoteAddress);
                clearInterval(udpConnections[remoteAddress].interval);
                delete udpConnections[remoteAddress];
            }
        }, 1000);
    }
    udpConnections[remoteAddress].count++;
    if (blacklist[remoteAddress]) {
        console.log(`Rejected UDP message from blacklisted IP: ${remoteAddress}`);
        return;
    }
});

udpServer.on('listening', () => {
    const address = udpServer.address();
    console.log(`UDP server listening ${address.address}:${address.port}`);
});
udpServer.bind(0);  // Bind to a random available port

const tcpPort = 5775;
tcpServer.listen(tcpPort, () => {
    console.log(`TCP server is listening on port ${tcpPort}`);
});

const app = express();
const proxy = httpProxy.createProxyServer({});

app.use((req, res, next) => {
    const remoteAddress = req.connection.remoteAddress;
    if (blacklist[remoteAddress]) {
        res.status(403).send('Forbidden');
        return;
    }

    const currentTime = Math.floor(Date.now() / 60000); 
    requestCounts[remoteAddress] = requestCounts[remoteAddress] || {};
    requestCounts[remoteAddress][currentTime] = (requestCounts[remoteAddress][currentTime] || 0) + 1;

    const requestCount = Object.values(requestCounts[remoteAddress]).reduce((a, b) => a + b, 0);

    if (requestCount > MAX_REQUESTS_PER_MINUTE) {
        console.log(`DDoS attack detected from ${remoteAddress}. Requests per minute: ${requestCount}`);
        if (!loggedIPs.has(remoteAddress)) {
            logDDoSAttack(remoteAddress, requestCount, 'HTTP');
        }
        addToBlacklist(remoteAddress);
        res.status(403).send('Forbidden');
    } else {
        next();
    }
});

app.use((req, res) => {
    const target = 'http://localhost';
    proxy.web(req, res, { target: `${target}${req.url}` });
});

// Redirect heavy traffic to another server
app.use((req, res, next) => {
    const remoteAddress = req.connection.remoteAddress;
    if (connections[remoteAddress] > MAX_CONNECTIONS_PER_IP) {
        console.log(`Redirecting heavy traffic from ${remoteAddress}`);
        res.redirect('http://109.71.253.231');
    } else {
        next();
    }
});

const httpPort = 8080;
app.listen(httpPort, () => {
    console.log(`HTTP server is listening on port ${httpPort}`);
});
