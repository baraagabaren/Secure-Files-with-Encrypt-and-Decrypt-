🔐 Secure Files (C# WinForms)

A simple Windows Forms application that lets you encrypt and decrypt files with a password.
Built with AES-GCM (256-bit) for strong encryption and PBKDF2 (HMAC-SHA256) for key derivation.

✨ Features

🔑 Password-based encryption (PBKDF2 with 200,000 iterations).

🔒 AES-256 GCM mode for secure encryption + authentication tag.

📝 Custom file header format storing:

Magic bytes (PWDF)

Version

Salt (16 bytes)

Nonce (12 bytes)

Tag (16 bytes)

Ciphertext

📂 Automatically saves encrypted/decrypted files to your Documents folder.

🖥️ Clean WinForms UI with two buttons: Encrypt File and Decrypt File.

🖥️ How It Works

Encrypt File

User selects a file path and enters a password.

A 16-byte salt and 12-byte nonce are generated.

PBKDF2 derives a 256-bit key from the password + salt.

File contents are encrypted with AES-GCM.

Output file: filename.ext.pwdf in the user’s Documents folder.

Decrypt File

Reads the header from the .pwdf file.

Re-derives the same key from the stored salt, iterations, and password.

Uses AES-GCM to verify tag + decrypt.

Restores the original file in Documents (removes .pwdf extension).

📂 Example

Input file:

C:\data\secret.txt


After encryption:

C:\Users\<YourUser>\Documents\secret.txt.pwdf


After decryption:

C:\Users\<YourUser>\Documents\secret.txt

🛠️ Technologies

C# .NET 6+

System.Security.Cryptography

WinForms

🚀 How to Run

Clone the repository:

git clone https://github.com/baraagabaren/Secure-Files.git


Open the project in Visual Studio.

Run the solution (F5).

Enter a file path + password → click Encrypt File or Decrypt File.

⚠️ Notes

If you enter the wrong password, decryption will fail with an authentication error.

This project is for learning purposes — do not use for production without a security review
