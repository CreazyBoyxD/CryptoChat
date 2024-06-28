# CryptoChat

CryptoChat is a secure chat application using AES for message encryption and RSA for secure key exchange. This project consists of two main components: the client and the server, both implemented in C# using WPF for the GUI.

## Features

- Secure communication using AES-128 for message encryption.
- RSA encryption for secure exchange of AES keys.
- Multi-client support on the server.
- Simple GUI for both client and server.

## Getting Started

### Prerequisites

- .NET Framework
- Visual Studio or any other C# IDE

### Clone the Repository

git clone https://github.com/CreazyBoyxD/CryptoChat.git

cd CryptoChat

### Open the Project

Open the solution file `CryptoChat.sln` in Visual Studio.

### Build and Run

1. **Server:**
   1. Set the `CryptoServer` project as the startup project.
   2. Build and run the server.
   3. The server's IP address and port will be displayed. You can modify the port if needed.
1. **Client:**
   1. Set the `CryptoChat` project as the startup project.
   2. Build and run the client.
   3. Enter the server's IP address and port.
   4. Click "Connect" to establish a connection with the server.

## How It Works

### RSA Key Exchange

- The server generates an RSA key pair (public and private keys).
- The server sends the RSA public key to the client.
- The client uses the RSA public key to encrypt its AES key and IV.
- The server decrypts the AES key and IV using its RSA private key.

### AES Message Encryption

- After the key exchange, the client and server use AES-256 for encrypting and decrypting messages.
- Messages are encrypted on the client side before being sent to the server.
- The server decrypts the received messages and can broadcast them to other connected clients.

## Code Overview

### Client

- `ClientWindow.xaml.cs`:
  - Establishes connection to the server.
  - Receives the RSA public key.
  - Sends the encrypted AES key and IV.
  - Encrypts and sends messages using AES.
  - Listens for incoming messages from the server and decrypts them.

### Server

- `ServerWindow.xaml.cs`:
  - Listens for incoming client connections.
  - Sends the RSA public key to the client.
  - Receives the encrypted AES key and IV from the client.
  - Decrypts and stores the AES key and IV.
  - Handles incoming messages from clients, decrypts them, and broadcasts them to other clients.
