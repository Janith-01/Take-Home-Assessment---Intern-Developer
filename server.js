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

    socket.once('data', (data) => {
        if (data[0] === 0x05) {
            socket.write(Buffer.from([0x05, 0x00]));
        }
    });

    // Handle authentication 
    socket.on('data', (data) => {
 
        if (data[1] === 0x01) {  
            const username = data.slice(2, data.indexOf(0, 2));
            const password = data.slice(data.indexOf(0, 2) + 1);

            if (username.toString() === USERNAME && password.toString() === PASSWORD) {
                socket.write(Buffer.from([0x05, 0x00])); 
            } else {
                socket.write(Buffer.from([0x05, 0x01]));
                socket.end();
                return;
            }
        }

        // Handle connection request
        const destinationPort = data.readUInt16BE(2);  // Destination port (2 bytes)
        const destinationHost = data.slice(4).toString();  // Destination host (IPv4)

        logConnection(socket, destinationHost, destinationPort);

        // Connect to the destination server
        const destinationSocket = net.createConnection(destinationPort, destinationHost, () => {
            socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        });

        // Forward data between client and destination
        socket.pipe(destinationSocket);
        destinationSocket.pipe(socket);

        destinationSocket.on('error', (err) => {
            console.error('Error with destination connection:', err);
            socket.end();
        });
    });
});

server.listen(PORT, () => {
    console.log(`SOCKS5 proxy server listening on port ${PORT}`);
});