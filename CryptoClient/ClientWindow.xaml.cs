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
        private RSA serverRsa; // RSA do szyfrowania klucza AES i IV
        private Thread listener; // Wątek do nasłuchiwania wiadomości od serwera
        private bool isListening; // Flaga określająca, czy klient nasłuchuje wiadomości

        public ClientWindow()
        {
            InitializeComponent(); // Inicjalizacja komponentów GUI
            aes = Aes.Create(); // Utworzenie instancji AES
            aes.KeySize = 128; // Ustawienie rozmiaru klucza AES na 128 bitów
            serverRsa = RSA.Create(); // Utworzenie instancji RSA
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

                ReceiveRSAPublicKey(); // Odbiór klucza publicznego RSA od serwera
                SendKeyAndIV(); // Wysłanie klucza AES i IV do serwera

                isListening = true; // Ustawienie flagi nasłuchiwania na true
                listener = new Thread(ListenForMessages); // Utworzenie wątku do nasłuchiwania wiadomości
                listener.IsBackground = true; // Ustawienie wątku jako wątek w tle
                listener.Start(); // Uruchomienie wątku
            }
            catch (Exception ex)
            {
                ChatHistory.AppendText($"Connection error: {ex.Message}\n"); // Obsługa błędów połączenia
            }
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            if (client != null && client.Connected)
            {
                isListening = false; // Ustawienie flagi nasłuchiwania na false
                client.Close(); // Zamknięcie połączenia z serwerem
                ChatHistory.AppendText("Disconnected from server.\n"); // Dodanie informacji do historii czatu

                ConnectButton.IsEnabled = true; // Włączenie przycisku "Connect"
                DisconnectButton.IsEnabled = false; // Wyłączenie przycisku "Disconnect"
            }
        }

        private void ReceiveRSAPublicKey()
        {
            byte[] lengthPrefix = new byte[4]; // Bufor do przechowywania długości klucza
            stream.Read(lengthPrefix, 0, lengthPrefix.Length); // Odczytanie długości klucza
            int keyLength = BitConverter.ToInt32(lengthPrefix, 0); // Konwersja długości klucza do int
            byte[] publicKeyBytes = new byte[keyLength]; // Bufor na klucz publiczny
            stream.Read(publicKeyBytes, 0, publicKeyBytes.Length); // Odczytanie klucza publicznego
            string publicKeyXml = Encoding.UTF8.GetString(publicKeyBytes); // Konwersja klucza publicznego do stringa
            serverRsa.FromXmlString(publicKeyXml); // Zaimportowanie klucza publicznego do RSA
            ChatHistory.AppendText("Received RSA public key from server.\n"); // Dodanie informacji do historii czatu
        }

        private void SendKeyAndIV()
        {
            byte[] key = aes.Key; // Pobranie klucza AES
            byte[] iv = aes.IV; // Pobranie IV AES

            byte[] encryptedKey = serverRsa.Encrypt(key, RSAEncryptionPadding.Pkcs1); // Szyfrowanie klucza AES za pomocą RSA
            byte[] encryptedIv = serverRsa.Encrypt(iv, RSAEncryptionPadding.Pkcs1); // Szyfrowanie IV za pomocą RSA

            stream.Write(encryptedKey, 0, encryptedKey.Length); // Wysłanie zaszyfrowanego klucza AES
            stream.Write(encryptedIv, 0, encryptedIv.Length); // Wysłanie zaszyfrowanego IV
            Console.WriteLine("Sent encrypted AES key and IV"); // Informacja o wysłaniu danych
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

            SendData(stream, encryptedMessage); // Wysłanie zaszyfrowanej wiadomości
            Console.WriteLine($"Sent encrypted message of length {encryptedMessage.Length}"); // Informacja o wysłaniu wiadomości

            ChatHistory.AppendText($"You: {message}\n"); // Dodanie wiadomości do historii czatu
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
                    if (encryptedMessage == null)
                    {
                        break; // Zakończenie nasłuchiwania jeśli serwer rozłączył
                    }

                    Console.WriteLine($"Received encrypted message of length {encryptedMessage.Length}"); // Informacja o odebranej wiadomości

                    string message = DecryptMessage(encryptedMessage); // Deszyfrowanie wiadomości
                    Dispatcher.Invoke(() => ChatHistory.AppendText($"{message}\n")); // Dodanie wiadomości do historii czatu
                }
            }
            catch (Exception ex)
            {
                if (isListening)
                {
                    Dispatcher.Invoke(() => ChatHistory.AppendText($"Error: {ex.Message}\n")); // Informacja o błędzie
                }
            }
        }

        private void SendData(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length); // Dodanie prefiksu długości wiadomości
            Console.WriteLine($"Sending message of length {data.Length}"); // Informacja o wysyłanej wiadomości
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
            Console.WriteLine($"Expecting message of length {messageLength}"); // Informacja o oczekiwanej długości wiadomości
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
    }
}