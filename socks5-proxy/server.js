const net = require('net');
const dotenv = require('dotenv');
dotenv.config();

const PORT = process.env.PORT || 1080;
const USERNAME = process.env.PROXY_USERNAME || 'admin';
const PASSWORD = process.env.PROXY_PASSWORD || 'password';

// SOCKS5 Protocol Constants
const SOCKS_VERSION = 0x05;
const AUTH_METHODS = {
    NO_AUTH: 0x00,
    USERNAME_PASSWORD: 0x02,
    NO_ACCEPTABLE: 0xFF
};
const AUTH_VERSION = 0x01;
const COMMANDS = {
    CONNECT: 0x01,
    BIND: 0x02,
    UDP_ASSOCIATE: 0x03
};
const ADDRESS_TYPES = {
    IPV4: 0x01,
    DOMAIN: 0x03,
    IPV6: 0x04
};
const REPLY_CODES = {
    SUCCESS: 0x00,
    GENERAL_FAILURE: 0x01,
    CONNECTION_NOT_ALLOWED: 0x02,
    NETWORK_UNREACHABLE: 0x03,
    HOST_UNREACHABLE: 0x04,
    CONNECTION_REFUSED: 0x05,
    TTL_EXPIRED: 0x06,
    COMMAND_NOT_SUPPORTED: 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED: 0x08
};

// Enhanced logging
function logConnection(socket, destinationHost, destinationPort, status = 'ATTEMPTING') {
    const timestamp = new Date().toISOString();
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[${timestamp}] ${status}: ${clientAddr} -> ${destinationHost}:${destinationPort}`);
}

function logError(message, error = null) {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] ERROR: ${message}`, error ? error.message : '');
}

// Parse SOCKS5 request and extract destination
function parseSOCKS5Request(data) {
    if (data.length < 7) {
        throw new Error('Invalid SOCKS5 request: too short');
    }

    const version = data[0];
    const cmd = data[1];
    const reserved = data[2];
    const addressType = data[3];

    if (version !== SOCKS_VERSION) {
        throw new Error(`Invalid SOCKS version: ${version}`);
    }

    let destAddr, destPort, responseData;

    switch (addressType) {
        case ADDRESS_TYPES.IPV4:
            if (data.length < 10) throw new Error('Invalid IPv4 request');
            destAddr = Array.from(data.slice(4, 8)).join('.');
            destPort = data.readUInt16BE(8);
            responseData = data.slice(4, 10);
            break;

        case ADDRESS_TYPES.DOMAIN:
            const domainLen = data[4];
            if (data.length < 7 + domainLen) throw new Error('Invalid domain request');
            destAddr = data.slice(5, 5 + domainLen).toString();
            destPort = data.readUInt16BE(5 + domainLen);
            responseData = data.slice(4, 7 + domainLen);
            break;

        case ADDRESS_TYPES.IPV6:
            if (data.length < 22) throw new Error('Invalid IPv6 request');
            // Convert IPv6 bytes to proper format
            const ipv6Bytes = data.slice(4, 20);
            const ipv6Segments = [];
            for (let i = 0; i < 16; i += 2) {
                ipv6Segments.push(ipv6Bytes.readUInt16BE(i).toString(16));
            }
            destAddr = ipv6Segments.join(':');
            destPort = data.readUInt16BE(20);
            responseData = data.slice(4, 22);
            break;

        default:
            throw new Error(`Unsupported address type: ${addressType}`);
    }

    return { cmd, addressType, destAddr, destPort, responseData };
}

// Create SOCKS5 response
function createSOCKS5Response(replyCode, addressType, responseData) {
    const response = Buffer.alloc(4 + responseData.length);
    response[0] = SOCKS_VERSION;
    response[1] = replyCode;
    response[2] = 0x00; // Reserved
    response[3] = addressType;
    responseData.copy(response, 4);
    return response;
}

// Handle client connections
const server = net.createServer((socket) => {
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[${new Date().toISOString()}] Client connected: ${clientAddr}`);

    let stage = 0; // 0: handshake, 1: auth, 2: request, 3: tunneling
    let destinationSocket = null;
    let isAuthenticated = false;

    // Set socket timeout to prevent hanging connections
    socket.setTimeout(30000);

    socket.on('timeout', () => {
        logError(`Socket timeout for client ${clientAddr}`);
        socket.destroy();
    });

    socket.on('data', (data) => {
        try {
            if (stage === 0) {
                // SOCKS5 handshake
                if (data.length < 3 || data[0] !== SOCKS_VERSION) {
                    throw new Error('Invalid SOCKS5 handshake');
                }

                const nmethods = data[1];
                const methods = data.slice(2, 2 + nmethods);

                // Check for supported authentication methods
                if (methods.includes(AUTH_METHODS.USERNAME_PASSWORD)) {
                    socket.write(Buffer.from([SOCKS_VERSION, AUTH_METHODS.USERNAME_PASSWORD]));
                    stage = 1;
                } else if (methods.includes(AUTH_METHODS.NO_AUTH)) {
                    socket.write(Buffer.from([SOCKS_VERSION, AUTH_METHODS.NO_AUTH]));
                    isAuthenticated = true;
                    stage = 2;
                } else {
                    socket.write(Buffer.from([SOCKS_VERSION, AUTH_METHODS.NO_ACCEPTABLE]));
                    socket.end();
                }
                return;
            }

            if (stage === 1) {
                // Username/password authentication (RFC 1929)
                if (data.length < 5 || data[0] !== AUTH_VERSION) {
                    socket.write(Buffer.from([AUTH_VERSION, 0x01])); // Auth failure
                    socket.end();
                    return;
                }

                const ulen = data[1];
                if (data.length < 3 + ulen) {
                    socket.write(Buffer.from([AUTH_VERSION, 0x01]));
                    socket.end();
                    return;
                }

                const username = data.slice(2, 2 + ulen).toString();
                const plen = data[2 + ulen];
                
                if (data.length < 3 + ulen + plen) {
                    socket.write(Buffer.from([AUTH_VERSION, 0x01]));
                    socket.end();
                    return;
                }

                const password = data.slice(3 + ulen, 3 + ulen + plen).toString();

                console.log(`[${new Date().toISOString()}] Auth attempt - Username: ${username}`);

                if (username === USERNAME && password === PASSWORD) {
                    socket.write(Buffer.from([AUTH_VERSION, 0x00])); // Success
                    isAuthenticated = true;
                    stage = 2;
                } else {
                    socket.write(Buffer.from([AUTH_VERSION, 0x01])); // Failure
                    logError(`Authentication failed for ${clientAddr}`);
                    socket.end();
                }
                return;
            }

            if (stage === 2) {
                // SOCKS5 request
                if (!isAuthenticated) {
                    logError('Request received without authentication');
                    socket.end();
                    return;
                }

                try {
                    const { cmd, addressType, destAddr, destPort, responseData } = parseSOCKS5Request(data);

                    if (cmd !== COMMANDS.CONNECT) {
                        const response = createSOCKS5Response(REPLY_CODES.COMMAND_NOT_SUPPORTED, addressType, responseData);
                        socket.write(response);
                        socket.end();
                        return;
                    }

                    logConnection(socket, destAddr, destPort, 'CONNECTING');

                    // Connect to destination
                    destinationSocket = net.createConnection(destPort, destAddr, () => {
                        logConnection(socket, destAddr, destPort, 'CONNECTED');
                        const response = createSOCKS5Response(REPLY_CODES.SUCCESS, addressType, responseData);
                        socket.write(response);
                        
                        // Start tunneling
                        socket.pipe(destinationSocket);
                        destinationSocket.pipe(socket);
                        stage = 3;
                    });

                    destinationSocket.on('error', (err) => {
                        logError(`Connection to ${destAddr}:${destPort} failed`, err);
                        
                        let replyCode = REPLY_CODES.GENERAL_FAILURE;
                        if (err.code === 'ECONNREFUSED') replyCode = REPLY_CODES.CONNECTION_REFUSED;
                        else if (err.code === 'EHOSTUNREACH') replyCode = REPLY_CODES.HOST_UNREACHABLE;
                        else if (err.code === 'ENETUNREACH') replyCode = REPLY_CODES.NETWORK_UNREACHABLE;

                        const response = createSOCKS5Response(replyCode, addressType, responseData);
                        socket.write(response);
                        socket.end();
                    });

                    destinationSocket.on('end', () => {
                        socket.end();
                    });

                } catch (parseError) {
                    logError('Failed to parse SOCKS5 request', parseError);
                    socket.end();
                }
            }
        } catch (error) {
            logError(`Error handling data from ${clientAddr}`, error);
            socket.end();
        }
    });

    socket.on('end', () => {
        console.log(`[${new Date().toISOString()}] Client disconnected: ${clientAddr}`);
        if (destinationSocket && !destinationSocket.destroyed) {
            destinationSocket.end();
        }
    });

    socket.on('error', (err) => {
        logError(`Socket error for ${clientAddr}`, err);
        if (destinationSocket && !destinationSocket.destroyed) {
            destinationSocket.destroy();
        }
    });

    socket.on('close', () => {
        if (destinationSocket && !destinationSocket.destroyed) {
            destinationSocket.destroy();
        }
    });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[INFO] Shutting down SOCKS5 proxy server...');
    server.close(() => {
        console.log('[INFO] Server closed');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('\n[INFO] Received SIGTERM, shutting down gracefully...');
    server.close(() => {
        console.log('[INFO] Server closed');
        process.exit(0);
    });
});

server.listen(PORT, () => {
    console.log(`[${new Date().toISOString()}] SOCKS5 proxy server listening on port ${PORT}`);
    console.log(`[INFO] Authentication: ${USERNAME}:${PASSWORD}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[ERROR] Port ${PORT} is already in use`);
    } else {
        console.error('[ERROR] Server error:', err);
    }
    process.exit(1);
});