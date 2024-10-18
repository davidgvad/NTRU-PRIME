# NTRU Cryptosystem Implementation

![License](https://img.shields.io/github/license/davidgvad/NTRU-PRIME)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Build Status](https://img.shields.io/github/workflow/status/davidgvad/NTRU-PRIME/NameOfYourWorkflowFile?branch=main)

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)

## Description
The **NTRU** project is a Python implementation of the NTRU cryptosystem, a lattice-based public key cryptosystem designed for efficient encryption and decryption. This project provides functionalities for key generation, encryption, and decryption, ensuring secure communication based on advanced mathematical constructs.

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

### Key Generation
Generate a pair of public and private keys.
```bash
python scripts/ntru.py gen 167 3 128 PRIV_KEY_FILE.npz PUB_KEY_FILE.npz
