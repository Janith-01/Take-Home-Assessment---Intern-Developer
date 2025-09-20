# SOCKS5 Proxy Server

This is a simple **SOCKS5 proxy server** built using **Node.js**. The server listens for incoming client connections, authenticates using a hardcoded username/password, and forwards traffic to the requested destination. It also logs each connection, including the source IP, destination host, and port.

## Features

- **SOCKS5 Protocol**: Handles the SOCKS5 handshake, authentication, and connection forwarding.
- **Authentication**: Uses hardcoded username and password for client authentication.
- **Logging**: Logs connection details including source IP, destination host, and port.
- **Configuration**: Easily configurable using environment variables (`.env` file).
  
## Prerequisites

- **Node.js** (v14 or later).
- **npm** (Node Package Manager).

## Setup Instructions

### 1. Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/Janith-01/Take-Home-Assessment---Intern-Developer.git
cd socks5-proxy