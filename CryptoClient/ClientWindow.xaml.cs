using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Input;

namespace CryptoChat
{
    public partial class ClientWindow : Window
    {
        private TcpClient client;
        private NetworkStream stream;
        private Aes aes;
        private RSA serverRsa;
        private Thread listener;
        private bool isListening;

        public ClientWindow()
        {
            InitializeComponent();
            aes = Aes.Create();
            aes.KeySize = 128;
            serverRsa = RSA.Create();
        }

        private void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                client = new TcpClient(ServerIP.Text, int.Parse(ServerPort.Text));
                stream = client.GetStream();
                ChatHistory.AppendText("Connected to server.\n");

                ConnectButton.IsEnabled = false;
                DisconnectButton.IsEnabled = true;

                // Receive RSA public key from the server
                ReceiveRSAPublicKey();

                // Send AES key and IV to the server
                SendKeyAndIV();

                // Start listening for messages from server
                isListening = true;
                listener = new Thread(ListenForMessages);
                listener.IsBackground = true;
                listener.Start();
            }
            catch (Exception ex)
            {
                ChatHistory.AppendText($"Connection error: {ex.Message}\n");
            }
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            if (client != null && client.Connected)
            {
                isListening = false;
                client.Close();
                ChatHistory.AppendText("Disconnected from server.\n");

                ConnectButton.IsEnabled = true;
                DisconnectButton.IsEnabled = false;
            }
        }

        private void ReceiveRSAPublicKey()
        {
            byte[] lengthPrefix = new byte[4];
            stream.Read(lengthPrefix, 0, lengthPrefix.Length);
            int keyLength = BitConverter.ToInt32(lengthPrefix, 0);
            byte[] publicKeyBytes = new byte[keyLength];
            stream.Read(publicKeyBytes, 0, publicKeyBytes.Length);
            string publicKeyXml = Encoding.UTF8.GetString(publicKeyBytes);
            serverRsa.FromXmlString(publicKeyXml);
            ChatHistory.AppendText("Received RSA public key from server.\n");
        }

        private void SendKeyAndIV()
        {
            byte[] key = aes.Key;
            byte[] iv = aes.IV;

            // Encrypt AES key and IV with server's public RSA key using Pkcs1 padding
            byte[] encryptedKey = serverRsa.Encrypt(key, RSAEncryptionPadding.Pkcs1);
            byte[] encryptedIv = serverRsa.Encrypt(iv, RSAEncryptionPadding.Pkcs1);

            // Send encrypted AES key and IV
            stream.Write(encryptedKey, 0, encryptedKey.Length);
            stream.Write(encryptedIv, 0, encryptedIv.Length);
            Console.WriteLine("Sent encrypted AES key and IV");
        }

        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            SendMessage();
        }

        private void MessageBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                SendMessage();
            }
        }

        private void SendMessage()
        {
            if (client == null || !client.Connected) return;

            string message = MessageBox.Text;
            byte[] encryptedMessage = EncryptMessage(message);

            SendData(stream, encryptedMessage);
            Console.WriteLine($"Sent encrypted message of length {encryptedMessage.Length}");

            ChatHistory.AppendText($"You: {message}\n");
            MessageBox.Clear();
        }

        private byte[] EncryptMessage(string message)
        {
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(message);
                        }
                    }
                    return ms.ToArray();
                }
            }
        }

        private string DecryptMessage(byte[] encryptedMessage)
        {
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                using (var ms = new MemoryStream(encryptedMessage))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        private void ListenForMessages()
        {
            try
            {
                while (isListening)
                {
                    byte[] encryptedMessage = ReceiveData(stream);
                    if (encryptedMessage == null)
                    {
                        break; // Server disconnected
                    }

                    Console.WriteLine($"Received encrypted message of length {encryptedMessage.Length}");

                    string message = DecryptMessage(encryptedMessage);
                    Dispatcher.Invoke(() => ChatHistory.AppendText($"{message}\n"));
                }
            }
            catch (Exception ex)
            {
                if (isListening)
                {
                    Dispatcher.Invoke(() => ChatHistory.AppendText($"Error: {ex.Message}\n"));
                }
            }
        }

        private void SendData(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            Console.WriteLine($"Sending message of length {data.Length}");
            stream.Write(lengthPrefix, 0, lengthPrefix.Length);
            stream.Write(data, 0, data.Length);
        }

        private byte[] ReceiveData(NetworkStream stream)
        {
            byte[] lengthPrefix = new byte[4];
            int bytesRead = stream.Read(lengthPrefix, 0, lengthPrefix.Length);
            if (bytesRead == 0)
            {
                return null; // Server disconnected
            }

            int messageLength = BitConverter.ToInt32(lengthPrefix, 0);
            Console.WriteLine($"Expecting message of length {messageLength}");
            byte[] buffer = new byte[messageLength];
            bytesRead = 0;

            while (bytesRead < messageLength)
            {
                int read = stream.Read(buffer, bytesRead, messageLength - bytesRead);
                if (read == 0)
                {
                    return null; // Server disconnected
                }
                bytesRead += read;
            }

            return buffer;
        }
    }
}