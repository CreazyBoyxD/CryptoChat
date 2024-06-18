# CryptoChat

CryptoChat is a secure chat application that uses AES encryption to ensure the privacy and security of messages exchanged between clients and a server.

## Features

- **AES Encryption**: All messages are encrypted using the AES encryption standard to ensure secure communication.
- **Real-time Messaging**: Clients can send and receive messages in real-time.
- **Multiple Clients**: The server can handle multiple client connections simultaneously.
- **Connection Status Indicator**: The client application shows the connection status to the server.

## Getting Started

### Prerequisites

- .NET Framework or .NET Core
- Visual Studio or any compatible C# IDE

### Running the Server

1. Open the `CryptoServer` project in Visual Studio.
2. Build the project.
3. Run the `ServerWindow.xaml`.

### Running the Client

1. Open the `CryptoChat` project in Visual Studio.
2. Build the project.
3. Run the `ClientWindow.xaml`.

### Usage

1. Start the server application.
2. Start the client application.
3. Enter the server IP and port in the client application.
4. Click `Connect` to connect to the server.
5. Enter your message in the `MessageBox` and click `Send` or press `Enter` to send the message.
6. The server will broadcast the message to all connected clients.
