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
        private TcpClient client; // Klient TCP do połączenia z serwerem
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
            diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;
            rsa = RSA.Create(); // Utworzenie instancji RSA
            serverRsa = RSA.Create(); // Utworzenie instancji RSA do weryfikacji podpisów
        }

        private void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                client = new TcpClient(ServerIP.Text, int.Parse(ServerPort.Text)); // Połączenie z serwerem
                stream = client.GetStream(); // Uzyskanie strumienia sieciowego
                ChatHistory.AppendText("Connected to server.\n"); // Dodanie informacji do historii czatu

                ConnectButton.IsEnabled = false; // Wyłączenie przycisku "Connect"
                DisconnectButton.IsEnabled = true; // Włączenie przycisku "Disconnect"

                SendPublicKey(); // Wysłanie klucza publicznego Diffie-Hellmana do serwera
                ReceivePublicKey(); // Odbiór klucza publicznego serwera

                SendClientRsaPublicKey(); // Wysłanie klucza publicznego RSA klienta do serwera

                // Wygenerowanie wspólnego sekretu i użycie go do utworzenia klucza AES
                byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));
                aes.Key = sharedSecret;
                aes.IV = new byte[aes.BlockSize / 8]; // Można zmodyfikować, aby lepiej zabezpieczyć IV

                isListening = true; // Ustawienie flagi nasłuchiwania na true
                listener = new Thread(ListenForMessages); // Utworzenie wątku do nasłuchiwania wiadomości
                listener.IsBackground = true; // Ustawienie wątku jako wątek w tle
                listener.Start(); // Uruchomienie wątku
            }
            catch (Exception ex)
            {
                AppendChatHistory($"Connection error: {ex.Message}\n"); // Obsługa błędów połączenia
            }
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            if (client != null && client.Connected)
            {
                isListening = false; // Ustawienie flagi nasłuchiwania na false
                client.Close(); // Zamknięcie połączenia z serwerem
                AppendChatHistory("Disconnected from server.\n"); // Dodanie informacji do historii czatu

                ConnectButton.IsEnabled = true; // Włączenie przycisku "Connect"
                DisconnectButton.IsEnabled = false; // Wyłączenie przycisku "Disconnect"
            }
        }

        private void SendPublicKey()
        {
            byte[] publicKey = diffieHellman.PublicKey.ToByteArray();
            SendData(stream, publicKey); // Wysłanie klucza publicznego
            AppendChatHistory("Sent Diffie-Hellman public key to server.\n"); // Dodanie informacji do historii czatu
        }

        private void ReceivePublicKey()
        {
            serverPublicKey = ReceiveData(stream); // Odbiór klucza publicznego serwera do Diffie-Hellmana
            AppendChatHistory($"Received Diffie-Hellman public key from server: {Convert.ToBase64String(serverPublicKey)}\n"); // Dodanie informacji do historii czatu

            byte[] rsaPublicKeyBytes = ReceiveData(stream); // Odbiór klucza publicznego serwera do weryfikacji podpisów
            string rsaPublicKeyXml = Encoding.UTF8.GetString(rsaPublicKeyBytes);
            serverRsa.FromXmlString(rsaPublicKeyXml); // Zaimportowanie klucza publicznego RSA serwera
            AppendChatHistory($"Received RSA public key from server: {rsaPublicKeyXml}\n"); // Dodanie informacji do historii czatu
        }

        private void SendClientRsaPublicKey()
        {
            string publicKeyXml = rsa.ToXmlString(false);
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKeyXml);
            SendData(stream, publicKeyBytes); // Wysłanie klucza publicznego
            AppendChatHistory($"Sent RSA public key to server: {publicKeyXml}\n"); // Dodanie informacji do historii czatu
        }

        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            SendMessage(); // Wysłanie wiadomości
        }

        private void MessageBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                SendMessage(); // Wysłanie wiadomości po naciśnięciu Enter
            }
        }

        private void SendMessage()
        {
            if (client == null || !client.Connected) return;

            string message = MessageBox.Text; // Pobranie wiadomości z pola tekstowego
            byte[] encryptedMessage = EncryptMessage(message); // Szyfrowanie wiadomości
            byte[] hash = ComputeHash(message); // Obliczenie skrótu wiadomości
            byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Podpisanie skrótu

            if (showLogs)
            {
                Log($"Sending message: {message}"); // Dodanie logu wysyłanej wiadomości
                Log($"Sending signature: {Convert.ToBase64String(signature)}"); // Dodanie logu podpisu
                Log($"Computed hash: {Convert.ToBase64String(hash)}"); // Dodanie logu obliczonego hasha
            }

            SendData(stream, encryptedMessage); // Wysłanie zaszyfrowanej wiadomości
            SendData(stream, signature); // Wysłanie podpisu

            AppendChatHistory($"You: {message}\n"); // Dodanie wiadomości do historii czatu
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
                        Log($"Received message: {message}"); // Dodanie logu otrzymanej wiadomości
                        Log($"Received signature: {Convert.ToBase64String(signature)}"); // Dodanie logu otrzymanego podpisu
                        Log($"Computed hash: {Convert.ToBase64String(hash)}"); // Dodanie logu obliczonego hasha
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
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
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
                AppendChatHistory($"{DateTime.Now}: {message}\n"); // Dodanie wiadomości do logu
            });
        }

        private void AppendChatHistory(string message)
        {
            ChatHistory.AppendText(message);
            ChatHistory.ScrollToEnd(); // Auto-scroll to the end
        }

        private void ShowLogsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            showLogs = true;
        }

        private void ShowLogsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            showLogs = false;
        }
    }
}