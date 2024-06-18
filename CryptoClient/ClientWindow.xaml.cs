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
        private RSA rsa;
        private Thread listener;
        private bool isListening;

        public ClientWindow()
        {
            InitializeComponent();
            aes = Aes.Create();
            rsa = RSA.Create();
        }

        private void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                client = new TcpClient(ServerIP.Text, int.Parse(ServerPort.Text));
                stream = client.GetStream();
                ChatHistory.AppendText("Connected to server.\n");

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
            }
        }

        private void SendKeyAndIV()
        {
            byte[] key = aes.Key;
            byte[] iv = aes.IV;
            stream.Write(key, 0, key.Length);
            stream.Write(iv, 0, iv.Length);
            Console.WriteLine("Sent AES key and IV");
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
                if (isListening) // Log the error only if we are still supposed to be listening
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
