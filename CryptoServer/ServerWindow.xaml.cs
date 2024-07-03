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
        private ECDiffieHellmanCng diffieHellman; // Diffie-Hellman do wymiany klucza AES
        private RSA rsa; // RSA do podpisywania wiadomości

        public ServerWindow()
        {
            InitializeComponent(); // Inicjalizacja komponentów GUI
            diffieHellman = new ECDiffieHellmanCng(); // Utworzenie instancji Diffie-Hellmana
            diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash; // Ustawienie funkcji do wyprowadzania klucza
            diffieHellman.HashAlgorithm = CngAlgorithm.Sha256; // Ustawienie algorytmu haszującego na SHA256
            rsa = RSA.Create(); // Utworzenie instancji RSA
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
            listener = new TcpListener(IPAddress.Any, port); // Utworzenie nasłuchiwacza TCP na wszystkich interfejsach i podanym porcie
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
                    ClientInfo clientInfo = new ClientInfo { Client = client, Aes = Aes.Create(), Id = ((IPEndPoint)client.Client.RemoteEndPoint).Port.ToString() }; // Utworzenie informacji o kliencie
                    clients.Add(clientInfo); // Dodanie klienta do listy klientów

                    SendPublicKey(stream); // Wysłanie klucza publicznego Diffie-Hellmana do klienta
                    ReceivePublicKey(stream, clientInfo); // Odbiór klucza publicznego klienta i wygenerowanie wspólnego sekretu
                    SendRSAPublicKey(stream); // Wysłanie klucza publicznego RSA do klienta
                    ReceiveClientRsaPublicKey(stream, clientInfo); // Odbiór klucza publicznego RSA klienta

                    Thread clientThread = new Thread(() => HandleClient(clientInfo)); // Utworzenie wątku do obsługi klienta
                    clientThread.Start(); // Uruchomienie wątku
                }
                catch (SocketException)
                {
                    break; // Wyjście z pętli w przypadku błędu gniazda
                }
            }
        }

        private void SendPublicKey(NetworkStream stream)
        {
            byte[] publicKey = diffieHellman.PublicKey.ToByteArray(); // Pobranie klucza publicznego Diffie-Hellmana jako tablicy bajtów
            SendData(stream, publicKey); // Wysłanie klucza publicznego do klienta
            Log("Sent Diffie-Hellman public key to client"); // Dodanie informacji do logu
        }

        private void ReceivePublicKey(NetworkStream stream, ClientInfo clientInfo)
        {
            byte[] clientPublicKey = ReceiveData(stream); // Odbiór klucza publicznego klienta

            // Wygenerowanie wspólnego sekretu i użycie go do utworzenia klucza AES
            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));
            clientInfo.Aes.Key = sharedSecret;
            clientInfo.Aes.IV = new byte[clientInfo.Aes.BlockSize / 8]; // Ustawienie IV (Initialization Vector) na odpowiednią długość (16 bajtów dla AES)

            Log($"Received Diffie-Hellman public key from client and generated shared secret. Client public key: {Convert.ToBase64String(clientPublicKey)}"); // Dodanie informacji do logu
        }

        private void SendRSAPublicKey(NetworkStream stream)
        {
            string publicKeyXml = rsa.ToXmlString(false); // Eksportowanie tylko klucza publicznego RSA w formacie XML
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKeyXml); // Konwersja klucza publicznego do tablicy bajtów
            SendData(stream, publicKeyBytes); // Wysłanie klucza publicznego do klienta
            Log($"Sent RSA public key to client: {publicKeyXml}"); // Dodanie informacji do logu
        }

        private void ReceiveClientRsaPublicKey(NetworkStream stream, ClientInfo clientInfo)
        {
            byte[] rsaPublicKeyBytes = ReceiveData(stream); // Odbiór klucza publicznego klienta
            string rsaPublicKeyXml = Encoding.UTF8.GetString(rsaPublicKeyBytes); // Konwersja klucza publicznego do formatu XML
            clientInfo.ClientRsa = RSA.Create(); // Utworzenie instancji RSA dla klienta
            clientInfo.ClientRsa.FromXmlString(rsaPublicKeyXml); // Importowanie klucza publicznego RSA klienta
            Log($"Received RSA public key from client: {rsaPublicKeyXml}"); // Dodanie informacji do logu
        }

        private void HandleClient(ClientInfo clientInfo)
        {
            TcpClient client = clientInfo.Client; // Pobranie klienta
            NetworkStream stream = client.GetStream(); // Uzyskanie strumienia sieciowego

            try
            {
                while (true)
                {
                    byte[] encryptedMessage = ReceiveData(stream); // Odbiór zaszyfrowanej wiadomości
                    byte[] signature = ReceiveData(stream); // Odbiór podpisu wiadomości

                    if (encryptedMessage == null || signature == null)
                    {
                        break; // Zakończenie nasłuchiwania jeśli klient rozłączył
                    }

                    string message = DecryptMessage(encryptedMessage, clientInfo.Aes); // Deszyfrowanie wiadomości
                    byte[] hash = ComputeHash(message); // Obliczenie skrótu wiadomości

                    Log($"Received message: {message}"); // Dodanie logu otrzymanej wiadomości
                    Log($"Received signature: {Convert.ToBase64String(signature)}"); // Dodanie logu otrzymanego podpisu
                    Log($"Computed hash: {Convert.ToBase64String(hash)}"); // Dodanie logu obliczonego hasha

                    bool isValid = clientInfo.ClientRsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Weryfikacja podpisu
                    if (isValid)
                    {
                        Log($"Client {clientInfo.Id}: {message}"); // Dodanie informacji o poprawnej wiadomości do logu
                        byte[] response = EncryptMessage($"{clientInfo.Id}: {message}", clientInfo.Aes); // Szyfrowanie odpowiedzi
                        byte[] responseSignature = SignMessage($"{clientInfo.Id}: {message}"); // Podpisanie odpowiedzi
                        BroadcastMessage(response, responseSignature, clientInfo); // Wysłanie odpowiedzi do wszystkich klientów
                    }
                    else
                    {
                        Log("Received message with invalid signature."); // Informacja o błędnym podpisie
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Exception: {ex.Message}"); // Informacja o błędzie
            }
            finally
            {
                clients.Remove(clientInfo); // Usunięcie klienta z listy klientów
                Log($"Client {clientInfo.Id} disconnected"); // Dodanie informacji o rozłączeniu klienta do logu
                client.Close(); // Zamknięcie połączenia z klientem
            }
        }

        private void BroadcastMessage(byte[] message, byte[] signature, ClientInfo sender)
        {
            foreach (var clientInfo in clients) // Iteracja przez wszystkich klientów
            {
                if (clientInfo != sender) // Pomijanie nadawcy wiadomości
                {
                    NetworkStream stream = clientInfo.Client.GetStream(); // Uzyskanie strumienia sieciowego
                    byte[] encryptedMessage = EncryptMessage(DecryptMessage(message, sender.Aes), clientInfo.Aes); // Szyfrowanie wiadomości dla każdego klienta
                    SendData(stream, encryptedMessage); // Wysłanie zaszyfrowanej wiadomości
                    SendData(stream, signature); // Wysłanie podpisu
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

        private byte[] ComputeHash(string message)
        {
            using (SHA256 sha256 = SHA256.Create()) // Utworzenie instancji SHA256
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(message)); // Obliczenie i zwrócenie skrótu wiadomości
            }
        }

        private byte[] SignMessage(string message)
        {
            byte[] hash = ComputeHash(message); // Obliczenie skrótu wiadomości
            return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Podpisanie skrótu wiadomości
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
        public RSA ClientRsa { get; set; } // Klucz publiczny klienta RSA
    }
}