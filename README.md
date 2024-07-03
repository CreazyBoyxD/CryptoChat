# CryptoChat

CryptoChat is a secure chat application using AES for message encryption, Diffie-Hellman for secure key exchange, and RSA for message signing. This project consists of two main components: the client and the server, both implemented in C# using WPF for the GUI.

## Features

- Secure communication using AES-256 for message encryption.
- Diffie-Hellman for secure exchange of AES keys.
- RSA for signing and verifying messages.
- Multi-client support on the server.
- Simple GUI for both client and server.
- Option to display detailed logs of the cryptographic operations.

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
2. **Client:**
   1. Set the `CryptoChat` project as the startup project.
   2. Build and run the client.
   3. Enter the server's IP address and port.
   4. Click "Connect" to establish a connection with the server.
   5. Use the "Show Logs" checkbox to toggle detailed logs.

## How It Works

### Diffie-Hellman Key Exchange

- The server and client each generate a Diffie-Hellman public/private key pair.
- The server sends its Diffie-Hellman public key to the client.
- The client sends its Diffie-Hellman public key to the server.
- Both the server and client use each other's public keys and their own private keys to compute a shared secret, which is used as the AES key.

### AES Message Encryption

- After the key exchange, the client and server use AES-256 for encrypting and decrypting messages.
- Messages are encrypted on the client side before being sent to the server.
- The server decrypts the received messages and can broadcast them to other connected clients.

### RSA Message Signing

- The server generates an RSA key pair (public and private keys).
- The server sends its RSA public key to the client.
- The client also generates an RSA key pair and sends its RSA public key to the server.
- Messages are signed using the sender's RSA private key and verified using the sender's RSA public key.

## Code Overview

### Client

- `ClientWindow.xaml.cs`:
  - Establishes connection to the server.
  - Exchanges Diffie-Hellman public keys with the server.
  - Computes the shared secret for AES encryption.
  - Exchanges RSA public keys with the server.
  - Encrypts and signs messages using AES and RSA.
  - Listens for incoming messages from the server, verifies signatures, and decrypts them.
  - Provides an option to show or hide detailed logs of cryptographic operations.

### Server

- `ServerWindow.xaml.cs`:
  - Listens for incoming client connections.
  - Exchanges Diffie-Hellman public keys with clients.
  - Computes the shared secret for AES encryption.
  - Exchanges RSA public keys with clients.
  - Decrypts and verifies incoming messages from clients.
  - Signs and encrypts messages for clients.
  - Broadcasts messages to other connected clients.