## AES Encryption/Decryption with Python and Javascript compatibility

This proof of concept aims to demonstrate the interoperability of encryption between Python and JavaScript. The system utilizes the AES 256 CBC algorithm to encrypt data in Python and decrypt it in JavaScript, and vice versa. The primary objective is to showcase the feasibility of securely encrypting and decrypting data across different programming languages.

## Instructions

To test the repository, you first need to install the required dependencies. To do this, run the following command in the terminal:

```bash
pip install -r requirements.txt
npm ci
```

Now you can first run the script to encryption with:

```bash
./encrypt.py input.json "your_secret_key"
```

The script will generate an encrypted file called `encrypted-input.txt` with the result.
Then, we can run the decryption passing the secret key previously used and the path of the encrypted file:

```bash
./decrypt.js encrypted-input.txt "your_secret_key"
```

We may see the decrypted content in the terminal.
