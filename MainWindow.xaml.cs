using System;
using System.Text;
using System.Windows;
using System.Security.Cryptography;
using System.IO;

namespace AES_Encrypt_Decrypt
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        

        public MainWindow()
        {
            InitializeComponent();
        }

        

        //Verschlüsseln

        public string Verschluesseln(string plainText)
        {
            try
            {
            string PasswordHash = passwordBox1.Password;
            string SaltKey = passwordBox2.Password;
            string VIKey = passwordBox3.Password;   /*max. 19 Zeichen*/

            if (VIKey.Length < 16)
            {
                MessageBox.Show("Die Länge des VIKeys stimmt nicht, er muss mindestens 16 und maximal 19 Zeichen lang sein. Ist er länger wird er gekürzt, ist er kürzer wird er verdoppelt und wieder gekürzt");
                VIKey += VIKey;
                VIKey += VIKey;
                VIKey += VIKey;
                VIKey += VIKey;
                VIKey = VIKey.Substring(0, 19);
                passwordBox3.Password = VIKey;
            }
            else if (VIKey.Length > 19)
            {
                MessageBox.Show("Die Länge des VIKeys stimmt nicht, er muss mindestens 16 und maximal 19 Zeichen lang sein. Ist er länger wird er gekürzt, ist er kürzer wird er verdoppelt und wieder gekürzt");
                VIKey = VIKey.Substring(0, 19);
                passwordBox3.Password = VIKey;
            }
            

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
            }
            catch (Exception) { return ""; }
        }



        //Entschlüsseln

        public string Entschluesseln(string encryptedText)
        {
            try
            {
            string PasswordHash = passwordBox1.Password;
            string SaltKey = passwordBox2.Password;
            string VIKey = passwordBox3.Password;   /*max. 19 Zeichen*/
            if (VIKey.Length > 19)
            {
                MessageBox.Show("Der VIKey ist zu lang, er darf maximal 19 Zeichen lang sein. Der Schlüssel wird auf 19 Zeichen gekürzt!!!");
                VIKey = VIKey.Substring(0, 19);
                passwordBox3.Password = VIKey;
            }

            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
            }
            catch (Exception) { return ""; }
        }

        public void button1_Click(object sender, RoutedEventArgs e)
        {
            label5.Content = "";
            if (textBox4.Text != "" || passwordBox1.Password != "" || passwordBox2.Password != "" || passwordBox3.Password != "")
            {
                textBox4.Text = Verschluesseln(textBox4.Text);
            }
            else
            {
                label5.Content = "Kein Text zum verschlüsseln vorhanden";
            }
            
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            label5.Content = "";
            if (textBox4.Text != "" || passwordBox1.Password != "" || passwordBox2.Password != "" || passwordBox3.Password != "")
            {
                textBox4.Text = Entschluesseln(textBox4.Text);
            }
            else
            {
                label5.Content = "Kein Text zum entschlüsseln vorhanden";
            }
            
        }

        private void button6_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            string copy = textBox4.Text;
            Clipboard.SetText(copy);
        } 
    }
}
