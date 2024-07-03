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
        private TcpClient client; // Obiekt TcpClient do połączenia z serwerem
        private NetworkStream stream; // Strumień sieciowy do przesyłania danych
        private Aes aes; // AES do szyfrowania i deszyfrowania wiadomości
        private ECDiffieHellmanCng diffieHellman; // Diffie-Hellman do wymiany klucza AES
        private RSA rsa; // RSA do podpisywania wiadomości
        private RSA serverRsa; // RSA do weryfikacji podpisów serwera
        private byte[] serverPublicKey; // Klucz publiczny serwera do Diffie-Hellmana
        private Thread listener; // Wątek do nasłuchiwania wiadomości od serwera
        private bool isListening; // Flaga określająca, czy klient nasłuchuje wiadomości
        private bool showLogs; // Flaga określająca, czy pokazywać logi

        public ClientWindow()
        {
            InitializeComponent(); // Inicjalizacja komponentów GUI
            aes = Aes.Create(); // Utworzenie instancji AES
            aes.KeySize = 256; // Ustawienie rozmiaru klucza AES na 256 bitów
            diffieHellman = new ECDiffieHellmanCng(); // Utworzenie instancji Diffie-Hellmana
            diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash; // Ustawienie funkcji do wyprowadzania klucza
            diffieHellman.HashAlgorithm = CngAlgorithm.Sha256; // Ustawienie algorytmu haszującego na SHA256
            rsa = RSA.Create(); // Utworzenie instancji RSA do podpisywania wiadomości
            serverRsa = RSA.Create(); // Utworzenie instancji RSA do weryfikacji podpisów serwera
        }

        private void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                client = new TcpClient(ServerIP.Text, int.Parse(ServerPort.Text)); // Połączenie z serwerem używając podanego adresu IP i portu
                stream = client.GetStream(); // Uzyskanie strumienia sieciowego
                ChatHistory.AppendText("Connected to server.\n"); // Dodanie informacji o połączeniu do historii czatu

                ConnectButton.IsEnabled = false; // Wyłączenie przycisku "Connect"
                DisconnectButton.IsEnabled = true; // Włączenie przycisku "Disconnect"

                SendPublicKey(); // Wysłanie klucza publicznego Diffie-Hellmana do serwera
                ReceivePublicKey(); // Odbiór klucza publicznego serwera

                SendClientRsaPublicKey(); // Wysłanie klucza publicznego RSA klienta do serwera

                // Wygenerowanie wspólnego sekretu i użycie go do utworzenia klucza AES
                byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));
                aes.Key = sharedSecret;
                aes.IV = new byte[aes.BlockSize / 8]; // Ustawienie IV (Initialization Vector) na odpowiednią długość (16 bajtów dla AES)

                isListening = true; // Ustawienie flagi nasłuchiwania na true
                listener = new Thread(ListenForMessages); // Utworzenie wątku do nasłuchiwania wiadomości
                listener.IsBackground = true; // Ustawienie wątku jako wątku w tle
                listener.Start(); // Uruchomienie wątku
            }
            catch (Exception ex)
            {
                AppendChatHistory($"Connection error: {ex.Message}\n"); // Obsługa błędów połączenia i dodanie informacji do historii czatu
            }
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            if (client != null && client.Connected)
            {
                isListening = false; // Ustawienie flagi nasłuchiwania na false
                client.Close(); // Zamknięcie połączenia z serwerem
                AppendChatHistory("Disconnected from server.\n"); // Dodanie informacji o rozłączeniu do historii czatu

                ConnectButton.IsEnabled = true; // Włączenie przycisku "Connect"
                DisconnectButton.IsEnabled = false; // Wyłączenie przycisku "Disconnect"
            }
        }

        private void SendPublicKey()
        {
            byte[] publicKey = diffieHellman.PublicKey.ToByteArray(); // Pobranie klucza publicznego Diffie-Hellmana jako tablicy bajtów
            SendData(stream, publicKey); // Wysłanie klucza publicznego do serwera
            AppendChatHistory("Sent Diffie-Hellman public key to server.\n"); // Dodanie informacji o wysłaniu klucza do historii czatu
        }

        private void ReceivePublicKey()
        {
            serverPublicKey = ReceiveData(stream); // Odbiór klucza publicznego serwera do Diffie-Hellmana
            AppendChatHistory($"Received Diffie-Hellman public key from server: {Convert.ToBase64String(serverPublicKey)}\n"); // Dodanie informacji o odbiorze klucza do historii czatu

            byte[] rsaPublicKeyBytes = ReceiveData(stream); // Odbiór klucza publicznego serwera do weryfikacji podpisów
            string rsaPublicKeyXml = Encoding.UTF8.GetString(rsaPublicKeyBytes); // Konwersja klucza publicznego do formatu XML
            serverRsa.FromXmlString(rsaPublicKeyXml); // Importowanie klucza publicznego RSA serwera
            AppendChatHistory($"Received RSA public key from server: {rsaPublicKeyXml}\n"); // Dodanie informacji o odbiorze klucza RSA do historii czatu
        }

        private void SendClientRsaPublicKey()
        {
            string publicKeyXml = rsa.ToXmlString(false); // Eksportowanie klucza publicznego RSA klienta w formacie XML
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKeyXml); // Konwersja klucza publicznego do tablicy bajtów
            SendData(stream, publicKeyBytes); // Wysłanie klucza publicznego do serwera
            AppendChatHistory($"Sent RSA public key to server: {publicKeyXml}\n"); // Dodanie informacji o wysłaniu klucza do historii czatu
        }

        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            SendMessage(); // Wywołanie metody do wysyłania wiadomości
        }

        private void MessageBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                SendMessage(); // Wysłanie wiadomości po naciśnięciu klawisza Enter
            }
        }

        private void SendMessage()
        {
            if (client == null || !client.Connected) return;

            string message = MessageBox.Text; // Pobranie wiadomości z pola tekstowego
            byte[] encryptedMessage = EncryptMessage(message); // Szyfrowanie wiadomości
            byte[] hash = ComputeHash(message); // Obliczenie skrótu wiadomości
            byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Podpisanie skrótu wiadomości

            if (showLogs)
            {
                Log($"Sending message: {message}"); // Logowanie wysyłanej wiadomości
                Log($"Sending signature: {Convert.ToBase64String(signature)}"); // Logowanie podpisu wiadomości
                Log($"Computed hash: {Convert.ToBase64String(hash)}"); // Logowanie obliczonego skrótu wiadomości
            }

            SendData(stream, encryptedMessage); // Wysłanie zaszyfrowanej wiadomości
            SendData(stream, signature); // Wysłanie podpisu wiadomości

            AppendChatHistory($"You: {message}\n"); // Dodanie wysłanej wiadomości do historii czatu
            MessageBox.Clear(); // Wyczyść pole tekstowe
        }

        private byte[] EncryptMessage(string message)
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

        private string DecryptMessage(byte[] encryptedMessage)
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

        private void ListenForMessages()
        {
            try
            {
                while (isListening)
                {
                    byte[] encryptedMessage = ReceiveData(stream); // Odbieranie zaszyfrowanej wiadomości
                    byte[] signature = ReceiveData(stream); // Odbieranie podpisu wiadomości

                    if (encryptedMessage == null || signature == null)
                    {
                        break; // Zakończenie nasłuchiwania jeśli serwer rozłączył
                    }

                    string message = DecryptMessage(encryptedMessage); // Deszyfrowanie wiadomości
                    byte[] hash = ComputeHash(message); // Obliczenie skrótu wiadomości

                    if (showLogs)
                    {
                        Log($"Received message: {message}"); // Logowanie otrzymanej wiadomości
                        Log($"Received signature: {Convert.ToBase64String(signature)}"); // Logowanie otrzymanego podpisu
                        Log($"Computed hash: {Convert.ToBase64String(hash)}"); // Logowanie obliczonego skrótu wiadomości
                    }

                    bool isValid = serverRsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Weryfikacja podpisu
                    if (isValid)
                    {
                        Dispatcher.Invoke(() => AppendChatHistory($"Server: {message}\n")); // Dodanie wiadomości do historii czatu
                    }
                    else
                    {
                        Dispatcher.Invoke(() => AppendChatHistory("Received message with invalid signature.\n")); // Informacja o błędnym podpisie
                    }
                }
            }
            catch (Exception ex)
            {
                if (isListening)
                {
                    Dispatcher.Invoke(() => AppendChatHistory($"Error: {ex.Message}\n")); // Informacja o błędzie
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
                return null; // Serwer rozłączył
            }

            int messageLength = BitConverter.ToInt32(lengthPrefix, 0); // Konwersja prefiksu do int
            byte[] buffer = new byte[messageLength]; // Bufor na wiadomość
            bytesRead = 0;

            while (bytesRead < messageLength)
            {
                int read = stream.Read(buffer, bytesRead, messageLength - bytesRead); // Odczytywanie wiadomości
                if (read == 0)
                {
                    return null; // Serwer rozłączył
                }
                bytesRead += read;
            }

            return buffer; // Zwrócenie odebranej wiadomości
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                AppendChatHistory($"{DateTime.Now}: {message}\n"); // Dodanie wiadomości do logu i przewinięcie do końca
            });
        }

        private void AppendChatHistory(string message)
        {
            ChatHistory.AppendText(message); // Dodanie wiadomości do historii czatu
            ChatHistory.ScrollToEnd(); // Automatyczne przewinięcie do końca
        }

        private void ShowLogsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            showLogs = true; // Ustawienie flagi logowania na true
        }

        private void ShowLogsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            showLogs = false; // Ustawienie flagi logowania na false
        }
    }
}