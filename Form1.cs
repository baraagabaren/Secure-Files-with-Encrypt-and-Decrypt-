using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq; 


namespace Secure_Files
{
    public partial class Form1 : Form
    {
        TextBox txtPath;
        TextBox txtPassword;
        Button btnStart;
        Button dec;

        const int KeySize = 32;     // 256-bit
        const int SaltSize = 16;    // 128-bit salt
        const int NonceSize = 12;   // 96-bit GCM nonce
        const int TagSize = 16;     // 128-bit tag
        const int Iterations = 200_000;
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("PWDF");
        const byte Version = 1;

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            txtPath = new TextBox
            {
                Location = new Point(10, 10),
                Width = 300,
                PlaceholderText = "Enter file path"
            };
            Controls.Add(txtPath);

            txtPassword = new TextBox
            {
                Location = new Point(10, 50),
                Width = 300,
                PlaceholderText = "Enter password",
                UseSystemPasswordChar = true
            };
            Controls.Add(txtPassword);

            btnStart = new Button
            {
                Location = new Point(10, 90),
                Text = "Encrypt File"
            };
            btnStart.Click += OpenTheFileAsync;
            Controls.Add(btnStart);
            dec = new Button
            {
                Location = new Point(50, 90),
                Text = "Decrypt File"
            };
            dec.Click += btnDecrypt_Click;
            Controls.Add(dec);

        }

        private async void OpenTheFileAsync(object sender, EventArgs e)
        {
            try
            {
                var inPath = txtPath.Text;

                if (!File.Exists(inPath))
                {
                    MessageBox.Show("The path does not exist.");
                    return;
                }
                if (string.IsNullOrWhiteSpace(txtPassword.Text))
                {
                    MessageBox.Show("Please enter a password.");
                    return;
                }

                txtPath.ReadOnly = true;
                btnStart.Enabled = false;

                // غيّر المجلد إذا بدك مكان مختلف
                string outputFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                await EncryptAsync(inPath, outputFolder, txtPassword.Text);

                MessageBox.Show("File encrypted successfully.");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
            finally
            {
                btnStart.Enabled = true;
                txtPath.ReadOnly = false;
            }
        }

        private static async Task EncryptAsync(string inputPath, string outputFolder, string password)
        {
            Directory.CreateDirectory(outputFolder);

            string outFile = System.IO.Path.Combine(
                outputFolder,
                System.IO.Path.GetFileName(inputPath) + ".pwdf"
            );

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

            byte[] key;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                key = kdf.GetBytes(KeySize);
            }

            byte[] plaintext = await File.ReadAllBytesAsync(inputPath);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];

            using (var gcm = new AesGcm(key))
            {
                gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            using (var fs = new FileStream(outFile, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write(Magic);       
                bw.Write(Version);     
                bw.Write(Iterations);  
                bw.Write(salt);        
                bw.Write(nonce);       
                bw.Write(tag);         
                bw.Write(ciphertext); 
            }

            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(salt);
        }
        public static async Task DecryptAsync(string inputPath, string outputFolder, string password)
        {
            Directory.CreateDirectory(outputFolder);

            byte[] magicRead;
            byte versionRead;
            int iterationsRead;
            byte[] salt;
            byte[] nonce;
            byte[] tag;
            byte[] ciphertext;

            using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: false))
            {
                magicRead = br.ReadBytes(4);
                if (magicRead.Length != 4 || !magicRead.SequenceEqual(Magic))
                    throw new InvalidDataException("Invalid file format (MAGIC).");

                versionRead = br.ReadByte();
                if (versionRead != Version)
                    throw new InvalidDataException($"Unsupported version: {versionRead}.");

                iterationsRead = br.ReadInt32();
                if (iterationsRead <= 0)
                    throw new InvalidDataException("Invalid KDF iterations.");

                salt = br.ReadBytes(SaltSize);
                if (salt.Length != SaltSize) throw new EndOfStreamException("Invalid salt length.");

                nonce = br.ReadBytes(NonceSize);
                if (nonce.Length != NonceSize) throw new EndOfStreamException("Invalid nonce length.");

                tag = br.ReadBytes(TagSize);
                if (tag.Length != TagSize) throw new EndOfStreamException("Invalid tag length.");

                long remaining = fs.Length - fs.Position;
                if (remaining < 0) throw new InvalidDataException("Corrupted file length.");
                ciphertext = br.ReadBytes(checked((int)remaining));
            }

            byte[] key;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterationsRead, HashAlgorithmName.SHA256))
            {
                key = kdf.GetBytes(KeySize);
            }

            byte[] plaintext = new byte[ciphertext.Length];
            try
            {
                using (var gcm = new AesGcm(key))
                {
                    gcm.Decrypt(nonce, ciphertext, tag, plaintext);
                }
            }
            finally
            {
            }

            string baseName = System.IO.Path.GetFileName(inputPath);
            string outName = baseName.EndsWith(".pwdf", System.StringComparison.OrdinalIgnoreCase)
                ? baseName.Substring(0, baseName.Length - ".pwdf".Length)
                : baseName + ".decrypted";

            string outPath = System.IO.Path.Combine(outputFolder, outName);

            await File.WriteAllBytesAsync(outPath, plaintext);

            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(salt);
        }
        private async void btnDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                string outputFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                await DecryptAsync(txtPath.Text, outputFolder, txtPassword.Text);
                MessageBox.Show("File decrypted successfully.");
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or file tampered (authentication failed).");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
        }

    }
}

