# NTRU Cryptosystem Implementation

![License](https://img.shields.io/github/license/davidgvad/NTRU-PRIME)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)


## Table of Contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)

## Description
The **NTRU** project is a Python implementation of the NTRU cryptosystem, a lattice-based public key cryptosystem known for its efficiency in encryption and decryption processes. This implementation offers functionalities for key generation, encryption, and decryption, ensuring secure communication based on sophisticated mathematical constructs. Key improvements in this version include the ability to handle large messages, which was a limitation in previous implementations. Additionally, this version boasts a significantly more user-friendly interface, thanks to a well-designed GUI built with PyQt5.

## Features
- **Key Generation**: Securely generate public and private keys.
- **Encryption**: Encrypt messages using the generated public key.
- **Decryption**: Decrypt messages using the private key.
- **Robust Logging**: Detailed logs for tracing and debugging.
- **Comprehensive Testing**: Unit tests to ensure reliability.
- **Modular Design**: Easily extendable and maintainable codebase.
- **Graphical User Interface**: User-friendly GUI built with PyQt5.

## Installation
1. **Clone the Repository**
    ```bash
    git clone https://github.com/davidgvad/ntru.git
    cd ntru
    ```

2. **Create a Virtual Environment**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

## Key Generation
Generate a pair of public and private keys.
```bash
python scripts/ntru.py gen 167 3 128 PRIV_KEY_FILE.npz PUB_KEY_FILE.npz
```
## Message Encryption
```bash
python scripts/ntru.py enc PUB_KEY_FILE.npz "your_message.txt" > "encrypted_message.txt"
```
## Message Decryption
```bash
python scripts/ntru.py dec PRIV_KEY_FILE.npz "encrypted_message.txt" > "decrypted_message.txt"
```
## Additional information
The above generation of the keys uses the CLI. However, the implementation is designed to favor the use of a graphical user interface (GUI) for encrypting and decrypting operations. Users are recommended to utilize the GUI method provided for a more intuitive and user-friendly experience, rather than the command-line interface (CLI) method.

