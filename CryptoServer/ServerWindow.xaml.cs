using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Windows;

namespace CryptoServer
{
    public partial class ServerWindow : Window
    {
        private TcpListener listener;
        private Thread listenerThread;
        private List<ClientInfo> clients = new List<ClientInfo>();

        public ServerWindow()
        {
            InitializeComponent();
            ServerIP.Text = GetLocalIPAddress();
            ServerPort.Text = "2137";
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            StartServer();
            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            StopServer();
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

        private void StartServer()
        {
            int port = int.Parse(ServerPort.Text);
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            listenerThread = new Thread(ListenForClients);
            listenerThread.IsBackground = true;
            listenerThread.Start();
            Log("Server started.");
        }

        private void StopServer()
        {
            if (listener != null)
            {
                listener.Stop();
                listenerThread?.Abort();
                clients.ForEach(client => client.Client.Close());
                clients.Clear();
                Log("Server stopped.");
            }
        }

        private void ListenForClients()
        {
            while (true)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    string clientEndPoint = ((IPEndPoint)client.Client.RemoteEndPoint).ToString();
                    Log($"Client connected from {clientEndPoint}");

                    ClientInfo clientInfo = new ClientInfo { Client = client, Aes = System.Security.Cryptography.Aes.Create(), Id = ((IPEndPoint)client.Client.RemoteEndPoint).Port.ToString() };
                    clients.Add(clientInfo);
                    Thread clientThread = new Thread(() => HandleClient(clientInfo));
                    clientThread.Start();
                }
                catch (SocketException)
                {
                    break;
                }
            }
        }

        private void HandleClient(ClientInfo clientInfo)
        {
            TcpClient client = clientInfo.Client;
            NetworkStream stream = client.GetStream();
            ReceiveKeyAndIV(stream, clientInfo.Aes);

            try
            {
                while (true)
                {
                    byte[] encryptedMessage = ReceiveData(stream);
                    if (encryptedMessage == null)
                    {
                        break;
                    }

                    string message = DecryptMessage(encryptedMessage, clientInfo.Aes);
                    Log($"Client {clientInfo.Id}: {message}");
                    byte[] response = EncryptMessage($"{clientInfo.Id}: {message}", clientInfo.Aes);
                    BroadcastMessage(response, clientInfo);
                }
            }
            catch (Exception ex)
            {
                Log($"Exception: {ex.Message}");
            }
            finally
            {
                clients.Remove(clientInfo);
                Log($"Client {clientInfo.Id} disconnected");
                client.Close();
            }
        }

        private void BroadcastMessage(byte[] message, ClientInfo sender)
        {
            foreach (var clientInfo in clients)
            {
                if (clientInfo != sender)
                {
                    NetworkStream stream = clientInfo.Client.GetStream();
                    byte[] encryptedMessage = EncryptMessage(DecryptMessage(message, sender.Aes), clientInfo.Aes);
                    SendData(stream, encryptedMessage);
                    Log($"Broadcasting message to {clientInfo.Id}");
                }
            }
        }

        private void ReceiveKeyAndIV(NetworkStream stream, System.Security.Cryptography.Aes aes)
        {
            byte[] key = new byte[32];
            stream.Read(key, 0, key.Length);
            aes.Key = key;

            byte[] iv = new byte[16];
            stream.Read(iv, 0, iv.Length);
            aes.IV = iv;
            Log("Received AES key and IV");
        }

        private byte[] EncryptMessage(string message, System.Security.Cryptography.Aes aes)
        {
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                using (var ms = new System.IO.MemoryStream())
                {
                    using (var cs = new System.Security.Cryptography.CryptoStream(ms, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
                    {
                        using (var sw = new System.IO.StreamWriter(cs))
                        {
                            sw.Write(message);
                        }
                    }
                    return ms.ToArray();
                }
            }
        }

        private string DecryptMessage(byte[] encryptedMessage, System.Security.Cryptography.Aes aes)
        {
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                using (var ms = new System.IO.MemoryStream(encryptedMessage))
                {
                    using (var cs = new System.Security.Cryptography.CryptoStream(ms, decryptor, System.Security.Cryptography.CryptoStreamMode.Read))
                    {
                        using (var sr = new System.IO.StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        private void SendData(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            stream.Write(lengthPrefix, 0, lengthPrefix.Length);
            stream.Write(data, 0, data.Length);
        }

        private byte[] ReceiveData(NetworkStream stream)
        {
            byte[] lengthPrefix = new byte[4];
            int bytesRead = stream.Read(lengthPrefix, 0, lengthPrefix.Length);
            if (bytesRead == 0)
            {
                return null;
            }

            int messageLength = BitConverter.ToInt32(lengthPrefix, 0);
            byte[] buffer = new byte[messageLength];
            bytesRead = 0;

            while (bytesRead < messageLength)
            {
                int read = stream.Read(buffer, bytesRead, messageLength - bytesRead);
                if (read == 0)
                {
                    return null;
                }
                bytesRead += read;
            }

            return buffer;
        }

        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "127.0.0.1";
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"{DateTime.Now}: {message}\n");
                LogTextBox.ScrollToEnd();
            });
        }
    }

    public class ClientInfo
    {
        public TcpClient Client { get; set; }
        public System.Security.Cryptography.Aes Aes { get; set; }
        public string Id { get; set; }
    }
}