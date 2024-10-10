**Password Cracker Tool**


**Introduction**:
This project is a password cracking tool developed in C that uses a dictionary attack to break password hashes. It supports multiple hashing algorithms such as MD5, SHA1, SHA224, SHA256, SHA384, and SHA512, utilizing OpenSSL’s cryptographic libraries for hash computation. The tool compares the user-provided hash against the hashes of common passwords from the rockyou.txt file (commonly used in password cracking).


**Features**:
Supports multiple hash algorithms: MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
Uses a dictionary attack to find matching passwords.
Calculates and compares the hash of each password from the dictionary file (rockyou.txt).
Tracks the time taken to find the password (if found).
Verifies hashes in hexadecimal format.


**How It Works**
The user provides a hashed password in hexadecimal format.
The tool reads each password from the dictionary (rockyou.txt) file.
For each password, it computes the hash using the specified algorithm (e.g., MD5, SHA256).
It compares the computed hash with the user-provided hash.
If a match is found, the corresponding plaintext password is displayed along with the time taken to crack it.


**Installation**
To compile the tool on a Linux system (like Kali Linux), follow these steps:

Ensure you have OpenSSL installed:

--->sudo apt-get install libssl-dev

Clone the repository:

--->git clone https://github.com/MAvinash24/password_cracker.git

Navigate to the project directory and compile the code:

--->cd password_cracker
--->gcc -o password_cracker password_cracker.c -lcrypto -lssl

Run the tool:

--->./password_cracker


Usage:
Enter the hashed password (in hexadecimal format) when prompted.
The tool will try to find the corresponding password using a dictionary attack from the rockyou.txt file.


__Example:__
OUTPUT be like:

Enter the hash (in hexadecimal format): 5d41402abc4b2a76b9719d911017c592
Verifying hash using algorithm: MD5
**Password found for MD5: hello
**Time taken to find the password: 0.004321 seconds


License
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as needed.
