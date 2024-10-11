# Password Cracker Tool




## Introduction
This project is a password cracking tool developed in C that uses a dictionary attack to break password hashes. It supports multiple hashing algorithms such as MD5, SHA1, SHA224, SHA256, SHA384, and SHA512, utilizing OpenSSL’s cryptographic libraries for hash computation. The tool compares the user-provided hash against the hashes of common passwords from the rockyou.txt file, a popular dataset used in password cracking.

#### The project also includes a list of the top 500 most commonly used passwords from rockyou.txt, which improves the chances of successful cracking by focusing on the weakest and most frequently reused passwords.


## Features
Supports multiple hash algorithms: MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
Uses a dictionary attack to find matching passwords.
Calculates and compares the hash of each password from the dictionary file (rockyou.txt).
Tracks the time taken to find the password (if found).
Verifies hashes in hexadecimal format.


## How It Works
The user provides a hashed password in hexadecimal format.
The tool reads each password from the dictionary (rockyou.txt) file.
For each password, it computes the hash using the specified algorithm (e.g., MD5, SHA256).
It compares the computed hash with the user-provided hash.
If a match is found, the corresponding plaintext password is displayed along with the time taken to crack it.

## Notice
All the files should be in same directory.{password_cracker.c , rockyou.txt }

## Installation
To compile the tool on a Linux system (like Kali Linux), follow these steps:

Ensure you have OpenSSL installed:

```
sudo apt update 
```
```
sudo apt-get install libssl-dev
```
Clone the repository:
```
git clone https://github.com/MAvinash24/password_cracker_.git
```
Navigate to the project directory and compile the code:
```
cd password_cracker_
```
```
gcc -o password_cracker password_cracker.c -lcrypto -lssl
```

Once the code is compiled, the next step is to acquire the rockyou.txt file, commonly used for dictionary attacks. **If needed** in real-time conditions, you can download and extract it manually from Kali Linux.However, if the full list is not needed, you can proceed to **run the tool** using the top 500 passwords already provided in my GitHub repository.
 

_Download manually (if necessary)_

1.Open Terminal
```
wget https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz
```
2.Unzip the rockyou.txt
```
gzip -d rockyou.txt.gz
```  
It has around 14 million passwords.

3.move it to your desired directory

## Run the tool
```
./password_cracker
```

Another command 
```
echo '5f4dcc3b5aa765d61d8327deb882cf99' | ./password_cracker | grep '**********'
```
It does not prompt for input because the hash is provided through the echo command. 
The use of grep is to filter the output and display only the line that contains ten red asterisks indicating the found password.

## Example
Enter the hashed password (in hexadecimal format) when prompted.
The tool will try to find the corresponding password using a dictionary attack from the rockyou.txt file.


### After executing:

Enter the hash (in hexadecimal format): 5d41402abc4b2a76b9719d911017c592


Verifying hash using algorithm: MD5


**********Password found for MD5: hello


**********Time taken to find the password: 0.004321 seconds


## NOTE:

While running the program, finding the correct password from the hash may take a considerable amount of time due to the approximately 14 million passwords being tested. However, it will eventually find the right answer, testing your patience.

In this scenario, you can create your own smaller sample file for testing by running the following command in your desired directory:
```
echo -e "password\n123456\nqwerty\nletmein" > rockyou.txt
```
