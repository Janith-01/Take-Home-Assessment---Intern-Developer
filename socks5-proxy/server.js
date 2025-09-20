const net = require('net');
const dotenv = require('dotenv');
dotenv.config();

const PORT = process.env.PORT || 1080;
const USERNAME = process.env.PROXY_USERNAME || 'admin';
const PASSWORD = process.env.PROXY_PASSWORD || 'password';

// Log connections
function logConnection(socket, destinationHost, destinationPort) {
    console.log(`Connection from ${socket.remoteAddress} to ${destinationHost}:${destinationPort}`);
}

// Handle client connections
const server = net.createServer((socket) => {
    console.log(`Client connected: ${socket.remoteAddress}`);

    let stage = 0; 

    let destinationSocket = null;

    socket.on('data', (data) => {
        if (stage === 0) {
            if (data[0] !== 0x05) {
                socket.end();
                return;
            }
         
            if (data.includes(0x02)) {
                socket.write(Buffer.from([0x05, 0x02])); 
                stage = 1;
            } else if (data.includes(0x00)) {
                socket.write(Buffer.from([0x05, 0x00])); 
                stage = 2;
            } else {
                socket.write(Buffer.from([0x05, 0xFF])); 
                socket.end();
            }
            return;
        }

        if (stage === 1) {
            
            if (data[0] !== 0x01) {
                socket.write(Buffer.from([0x01, 0x01])); // Failure response
                socket.end();
                return;
            }
            const ulen = data[1];
            const uname = data.slice(2, 2 + ulen).toString();
            const plen = data[2 + ulen];
            const passwd = data.slice(3 + ulen, 3 + ulen + plen).toString();

            console.log(`Username: ${uname}, Password: ${passwd}`);

            if (uname === USERNAME && passwd === PASSWORD) {
                socket.write(Buffer.from([0x01, 0x00])); // Authentication success
                stage = 2;
            } else {
                socket.write(Buffer.from([0x01, 0x01])); // Authentication failure
                socket.end();
            }
            return;
        }

        if (stage === 2) {
            // SOCKS5 request
            if (data.length < 7) {
                socket.end();
                return;
            }
            const cmd = data[1];
            const addressType = data[3];
            let destAddr, destPort, offset;

            if (addressType === 0x01) { // IPv4
                destAddr = data.slice(4, 8).join('.');
                destPort = data.readUInt16BE(8);
                offset = 10;
            } else if (addressType === 0x03) { // Domain
                const len = data[4];
                destAddr = data.slice(5, 5 + len).toString();
                destPort = data.readUInt16BE(5 + len);
                offset = 7 + len - 1;
            } else if (addressType === 0x04) { // IPv6
                destAddr = data.slice(4, 20).toString('hex').match(/.{1,4}/g).join(':');
                destPort = data.readUInt16BE(20);
                offset = 22;
            } else {
                socket.end();
                return;
            }

            logConnection(socket, destAddr, destPort);

            if (cmd !== 0x01) { 
                socket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]));
                socket.end();
                return;
            }

            destinationSocket = net.createConnection(destPort, destAddr, () => {
                socket.write(Buffer.from([0x05, 0x00, 0x00, addressType, ...data.slice(4, offset)]));
                // Pipe data after connection established
                socket.pipe(destinationSocket);
                destinationSocket.pipe(socket);
            });

            destinationSocket.on('error', (err) => {
                console.error('Error with destination connection:', err);
                socket.end();
            });

            socket.on('end', () => {
                if (destinationSocket) destinationSocket.end();
            });

            stage = 3; // Prevent further processing
        }
    });

    socket.on('error', (err) => {
        console.error('Socket error:', err);
        socket.end();
    });
});

server.listen(PORT, () => {
    console.log(`SOCKS5 proxy server listening on port ${PORT}`);
});
