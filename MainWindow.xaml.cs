using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Threading;

namespace CryptoChat
{
    public partial class MainWindow : Window
    {
        private TcpClient client;
        private NetworkStream stream;
        private Aes aes;
        private RSA rsa;

        public MainWindow()
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
                var listener = new Thread(ListenForMessages);
                listener.IsBackground = true;
                listener.Start();
            }
            catch (Exception ex)
            {
                ChatHistory.AppendText($"Connection error: {ex.Message}\n");
            }
        }

        private void SendKeyAndIV()
        {
            byte[] key = aes.Key;
            byte[] iv = aes.IV;
            stream.Write(key, 0, key.Length);
            stream.Write(iv, 0, iv.Length);
        }

        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            if (client == null || !client.Connected) return;

            string message = MessageBox.Text;
            byte[] encryptedMessage = EncryptMessage(message);
            stream.Write(encryptedMessage, 0, encryptedMessage.Length);
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
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                byte[] encryptedMessage = new byte[bytesRead];
                Array.Copy(buffer, encryptedMessage, bytesRead);
                string message = DecryptMessage(encryptedMessage);
                Dispatcher.Invoke(() => ChatHistory.AppendText($"Server: {message}\n"));
            }
        }
    }
}