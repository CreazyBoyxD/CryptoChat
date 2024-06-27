using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;

namespace CryptoServer
{
    public partial class ServerWindow : Window
    {
        private TcpListener listener; // Nasłuchiwacz TCP do akceptowania połączeń
        private Thread listenerThread; // Wątek do nasłuchiwania połączeń
        private List<ClientInfo> clients = new List<ClientInfo>(); // Lista połączonych klientów
        private RSA rsa; // RSA do szyfrowania klucza AES i IV

        public ServerWindow()
        {
            InitializeComponent(); // Inicjalizacja komponentów GUI
            rsa = RSA.Create(2048); // Utworzenie instancji RSA z kluczem 2048 bitów
            ServerIP.Text = GetLocalIPAddress(); // Wyświetlenie lokalnego adresu IP
            ServerPort.Text = "2137"; // Ustawienie domyślnego portu serwera
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            StartServer(); // Uruchomienie serwera
            StartButton.IsEnabled = false; // Wyłączenie przycisku "Start"
            StopButton.IsEnabled = true; // Włączenie przycisku "Stop"
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            StopServer(); // Zatrzymanie serwera
            StartButton.IsEnabled = true; // Włączenie przycisku "Start"
            StopButton.IsEnabled = false; // Wyłączenie przycisku "Stop"
        }

        private void StartServer()
        {
            int port = int.Parse(ServerPort.Text); // Pobranie portu z pola tekstowego
            listener = new TcpListener(IPAddress.Any, port); // Utworzenie nasłuchiwacza TCP
            listener.Start(); // Rozpoczęcie nasłuchiwania połączeń
            listenerThread = new Thread(ListenForClients); // Utworzenie wątku do nasłuchiwania klientów
            listenerThread.IsBackground = true; // Ustawienie wątku jako wątek w tle
            listenerThread.Start(); // Uruchomienie wątku
            Log("Server started."); // Dodanie informacji do logu
        }

        private void StopServer()
        {
            if (listener != null)
            {
                listener.Stop(); // Zatrzymanie nasłuchiwacza
                listenerThread?.Abort(); // Przerwanie wątku nasłuchiwacza
                clients.ForEach(client => client.Client.Close()); // Zamknięcie połączeń klientów
                clients.Clear(); // Wyczyszczenie listy klientów
                Log("Server stopped."); // Dodanie informacji do logu
            }
        }

        private void ListenForClients()
        {
            while (true)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient(); // Akceptowanie nowego połączenia
                    string clientEndPoint = ((IPEndPoint)client.Client.RemoteEndPoint).ToString(); // Pobranie adresu klienta
                    Log($"Client connected from {clientEndPoint}"); // Dodanie informacji do logu

                    NetworkStream stream = client.GetStream(); // Uzyskanie strumienia sieciowego
                    SendRSAPublicKey(stream); // Wysłanie klucza publicznego RSA do klienta

                    ClientInfo clientInfo = new ClientInfo { Client = client, Aes = Aes.Create(), Id = ((IPEndPoint)client.Client.RemoteEndPoint).Port.ToString() }; // Utworzenie informacji o kliencie
                    clients.Add(clientInfo); // Dodanie klienta do listy klientów
                    Thread clientThread = new Thread(() => HandleClient(clientInfo)); // Utworzenie wątku do obsługi klienta
                    clientThread.Start(); // Uruchomienie wątku
                }
                catch (SocketException)
                {
                    break; // Wyjście z pętli w przypadku błędu gniazda
                }
            }
        }

        private void SendRSAPublicKey(NetworkStream stream)
        {
            string publicKeyXml = rsa.ToXmlString(false); // Eksportowanie tylko klucza publicznego
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKeyXml); // Konwersja klucza publicznego do tablicy bajtów
            byte[] lengthPrefix = BitConverter.GetBytes(publicKeyBytes.Length); // Dodanie prefiksu długości
            stream.Write(lengthPrefix, 0, lengthPrefix.Length); // Wysłanie prefiksu długości
            stream.Write(publicKeyBytes, 0, publicKeyBytes.Length); // Wysłanie klucza publicznego
            Log("Sent RSA public key to client"); // Dodanie informacji do logu
        }

        private void ReceiveKeyAndIV(NetworkStream stream, Aes aes)
        {
            byte[] encryptedKey = new byte[256]; // Bufor na zaszyfrowany klucz AES
            stream.Read(encryptedKey, 0, encryptedKey.Length); // Odczytanie zaszyfrowanego klucza AES
            byte[] key = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1); // Odszyfrowanie klucza AES
            aes.Key = key; // Ustawienie klucza AES

            byte[] encryptedIv = new byte[256]; // Bufor na zaszyfrowane IV AES
            stream.Read(encryptedIv, 0, encryptedIv.Length); // Odczytanie zaszyfrowanego IV
            byte[] iv = rsa.Decrypt(encryptedIv, RSAEncryptionPadding.Pkcs1); // Odszyfrowanie IV
            aes.IV = iv; // Ustawienie IV AES

            Log("Received encrypted AES key and IV"); // Dodanie informacji do logu
        }

        private void HandleClient(ClientInfo clientInfo)
        {
            TcpClient client = clientInfo.Client; // Pobranie klienta
            NetworkStream stream = client.GetStream(); // Uzyskanie strumienia sieciowego
            ReceiveKeyAndIV(stream, clientInfo.Aes); // Odbiór klucza AES i IV od klienta

            try
            {
                while (true)
                {
                    byte[] encryptedMessage = ReceiveData(stream); // Odbiór zaszyfrowanej wiadomości
                    if (encryptedMessage == null)
                    {
                        break; // Zakończenie nasłuchiwania jeśli klient rozłączył
                    }

                    string message = DecryptMessage(encryptedMessage, clientInfo.Aes); // Deszyfrowanie wiadomości
                    Log($"Client {clientInfo.Id}: {message}"); // Dodanie informacji do logu
                    byte[] response = EncryptMessage($"{clientInfo.Id}: {message}", clientInfo.Aes); // Szyfrowanie odpowiedzi
                    BroadcastMessage(response, clientInfo); // Wysłanie odpowiedzi do wszystkich klientów
                }
            }
            catch (Exception ex)
            {
                Log($"Exception: {ex.Message}"); // Informacja o błędzie
            }
            finally
            {
                clients.Remove(clientInfo); // Usunięcie klienta z listy klientów
                Log($"Client {clientInfo.Id} disconnected"); // Dodanie informacji do logu
                client.Close(); // Zamknięcie połączenia z klientem
            }
        }

        private void BroadcastMessage(byte[] message, ClientInfo sender)
        {
            foreach (var clientInfo in clients) // Iteracja przez wszystkich klientów
            {
                if (clientInfo != sender) // Pomijanie nadawcy wiadomości
                {
                    NetworkStream stream = clientInfo.Client.GetStream(); // Uzyskanie strumienia sieciowego
                    byte[] encryptedMessage = EncryptMessage(DecryptMessage(message, sender.Aes), clientInfo.Aes); // Szyfrowanie wiadomości dla każdego klienta
                    SendData(stream, encryptedMessage); // Wysłanie zaszyfrowanej wiadomości
                    Log($"Broadcasting message to {clientInfo.Id}"); // Dodanie informacji do logu
                }
            }
        }

        private byte[] EncryptMessage(string message, Aes aes)
        {
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV)) // Utworzenie obiektu szyfrującego AES
            {
                using (var ms = new MemoryStream()) // Utworzenie strumienia pamięci
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) // Utworzenie strumienia szyfrowania
                    {
                        using (var sw = new StreamWriter(cs)) // Utworzenie strumienia zapisu
                        {
                            sw.Write(message); // Zapisanie zaszyfrowanej wiadomości
                        }
                    }
                    return ms.ToArray(); // Zwrócenie zaszyfrowanej wiadomości jako tablica bajtów
                }
            }
        }

        private string DecryptMessage(byte[] encryptedMessage, Aes aes)
        {
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV)) // Utworzenie obiektu deszyfrującego AES
            {
                using (var ms = new MemoryStream(encryptedMessage)) // Utworzenie strumienia pamięci z zaszyfrowaną wiadomością
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) // Utworzenie strumienia deszyfrowania
                    {
                        using (var sr = new StreamReader(cs)) // Utworzenie strumienia odczytu
                        {
                            return sr.ReadToEnd(); // Odczytanie i zwrócenie odszyfrowanej wiadomości
                        }
                    }
                }
            }
        }

        private void SendData(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length); // Dodanie prefiksu długości wiadomości
            stream.Write(lengthPrefix, 0, lengthPrefix.Length); // Wysłanie prefiksu długości
            stream.Write(data, 0, data.Length); // Wysłanie zaszyfrowanej wiadomości
        }

        private byte[] ReceiveData(NetworkStream stream)
        {
            byte[] lengthPrefix = new byte[4]; // Bufor na prefiks długości
            int bytesRead = stream.Read(lengthPrefix, 0, lengthPrefix.Length); // Odczytanie prefiksu długości
            if (bytesRead == 0)
            {
                return null; // Klient rozłączył
            }

            int messageLength = BitConverter.ToInt32(lengthPrefix, 0); // Konwersja prefiksu do int
            byte[] buffer = new byte[messageLength]; // Bufor na wiadomość
            bytesRead = 0;

            while (bytesRead < messageLength)
            {
                int read = stream.Read(buffer, bytesRead, messageLength - bytesRead); // Odczytywanie wiadomości
                if (read == 0)
                {
                    return null; // Klient rozłączył
                }
                bytesRead += read;
            }

            return buffer; // Zwrócenie odebranej wiadomości
        }

        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName()); // Pobranie informacji o hoście
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork) // Sprawdzenie, czy adres IP jest w rodzinie InterNetwork
                {
                    return ip.ToString(); // Zwrócenie lokalnego adresu IP
                }
            }
            return "127.0.0.1"; // Zwrócenie adresu localhost jeśli brak innych adresów
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"{DateTime.Now}: {message}\n"); // Dodanie wiadomości do logu
                LogTextBox.ScrollToEnd(); // Przewinięcie logu do końca
            });
        }
    }

    public class ClientInfo
    {
        public TcpClient Client { get; set; } // Klient TCP
        public Aes Aes { get; set; } // AES do szyfrowania i deszyfrowania wiadomości
        public string Id { get; set; } // Identyfikator klienta
    }
}