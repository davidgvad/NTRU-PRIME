#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NTRU v0.1

Usage:
  ntru.py [options] enc PUB_KEY_FILE [FILE]
  ntru.py [options] dec PRIV_KEY_FILE [FILE]
  ntru.py [options] gen N P Q PRIV_KEY_FILE PUB_KEY_FILE
  ntru.py (-h | --help)
  ntru.py --version

Options:
  -b, --block        Interpret input/output as block stream.
  -i, --poly-input   Interpret input as polynomial represented by integer array.
  -o, --poly-output  Interpret output as polynomial represented by integer array.
  -h, --help         Show this screen.
  --version          Show version.
  -d, --debug        Debug mode.
  -v, --verbose      Verbose mode.
"""

from docopt import docopt
from ntru.ntrucipher import NtruCipher
from ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
from padding.padding import padding_encode, padding_decode
import numpy as np
import sys
import logging
import math

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ntru")

# Global flags
debug_mode = False
verbose_mode = False


def generate_keys(N, p, q, private_key_path, public_key_path):
    """
    Generate public and private keys for NTRU.

    Args:
        N (int): Polynomial degree + 1.
        p (int): Parameter p.
        q (int): Parameter q.
        private_key_path (str): File path to save the private key.
        public_key_path (str): File path to save the public key.
    """
    ntru_cipher = NtruCipher(N, p, q)
    ntru_cipher.generate_random_keys()

    # Save private key
    private_key_coeffs = np.array(ntru_cipher.f_poly.all_coeffs()[::-1])
    private_key_p_coeffs = np.array(ntru_cipher.f_p_poly.all_coeffs()[::-1])
    np.savez_compressed(private_key_path, N=N, p=p, q=q, f=private_key_coeffs, f_p=private_key_p_coeffs)
    logger.info(f"Private key saved to {private_key_path}")

    # Save public key
    public_key_coeffs = np.array(ntru_cipher.h_poly.all_coeffs()[::-1])
    np.savez_compressed(public_key_path, N=N, p=p, q=q, h=public_key_coeffs)
    logger.info(f"Public key saved to {public_key_path}")


def encrypt_message(public_key_path, plaintext_bits, binary_output=False, use_block=False):
    """
    Encrypt plaintext using the NTRU cryptosystem.

    Args:
        public_key_path (str): File path to the public key.
        plaintext_bits (np.ndarray): Array of bits representing the plaintext.
        binary_output (bool): Flag to output binary data.
        use_block (bool): Flag to use block processing.

    Returns:
        np.ndarray: Encrypted bits.
    """
    public_key_data = np.load(public_key_path, allow_pickle=True)
    ntru_cipher = NtruCipher(int(public_key_data['N']), int(public_key_data['p']), int(public_key_data['q']))
    ntru_cipher.h_poly = Poly(public_key_data['h'].astype(int)[::-1], x).set_domain(ZZ)

    # Apply padding to the plaintext
    padded_plaintext = padding_encode(plaintext_bits, ntru_cipher.N)
    reshaped_plaintext = padded_plaintext.reshape((-1, ntru_cipher.N))

    encrypted_bits = np.array([])
    total_blocks = reshaped_plaintext.shape[0]

    for block_index, plaintext_block in enumerate(reshaped_plaintext, start=1):
        logger.info(f"Processing block {block_index} out of {total_blocks}")
        ciphertext_block = ntru_cipher.encrypt(
            Poly(plaintext_block[::-1], x).set_domain(ZZ),
            random_poly(ntru_cipher.N, int(math.sqrt(ntru_cipher.q)))
        ).all_coeffs()[::-1]

        # Pad ciphertext block if necessary
        if len(ciphertext_block) < ntru_cipher.N:
            ciphertext_block = np.pad(ciphertext_block, (0, ntru_cipher.N - len(ciphertext_block)), 'constant')

        encrypted_bits = np.concatenate((encrypted_bits, ciphertext_block))

    if binary_output:
        bits_per_coeff = int(math.log2(ntru_cipher.q))
        encrypted_bits = [[0 if bit == '0' else 1 for bit in np.binary_repr(int(coef), width=bits_per_coeff)] for coef in encrypted_bits]

    return np.array(encrypted_bits).flatten()


def decrypt_message(private_key_path, ciphertext_bits, binary_input=False, use_block=False):
    """
    Decrypt ciphertext using the NTRU cryptosystem.

    Args:
        private_key_path (str): File path to the private key.
        ciphertext_bits (np.ndarray): Array of bits representing the ciphertext.
        binary_input (bool): Flag to interpret input as binary.
        use_block (bool): Flag to use block processing.

    Returns:
        np.ndarray: Decrypted bits.
    """
    private_key_data = np.load(private_key_path, allow_pickle=True)
    ntru_cipher = NtruCipher(int(private_key_data['N']), int(private_key_data['p']), int(private_key_data['q']))
    ntru_cipher.f_poly = Poly(private_key_data['f'].astype(int)[::-1], x).set_domain(ZZ)
    ntru_cipher.f_p_poly = Poly(private_key_data['f_p'].astype(int)[::-1], x).set_domain(ZZ)

    if binary_input:
        bits_per_coeff = int(math.log2(ntru_cipher.q))
        padding_length = bits_per_coeff - (len(ciphertext_bits) % bits_per_coeff)
        if padding_length == bits_per_coeff:
            padding_length = 0
        padded_ciphertext = np.pad(ciphertext_bits, (0, padding_length), 'constant')
        reshaped_ciphertext = padded_ciphertext.reshape((-1, bits_per_coeff))
        ciphertext_bits = np.array([int("".join(bits.astype(str)), 2) for bits in reshaped_ciphertext])

    reshaped_ciphertext = ciphertext_bits.reshape((-1, ntru_cipher.N))
    decrypted_bits = np.array([])
    total_blocks = reshaped_ciphertext.shape[0]

    for block_index, ciphertext_block in enumerate(reshaped_ciphertext, start=1):
        logger.info(f"Processing block {block_index} out of {total_blocks}")
        decrypted_block = ntru_cipher.decrypt(
            Poly(ciphertext_block[::-1], x).set_domain(ZZ)
        ).all_coeffs()[::-1]

        # Pad decrypted block if necessary
        if len(decrypted_block) < ntru_cipher.N:
            decrypted_block = np.pad(decrypted_block, (0, ntru_cipher.N - len(decrypted_block)), 'constant')

        decrypted_bits = np.concatenate((decrypted_bits, decrypted_block))

    return padding_decode(decrypted_bits, ntru_cipher.N)


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        
        # Central Widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        # Encrypt Button
        self.encryptButton = QtWidgets.QPushButton(self.centralwidget)
        self.encryptButton.setGeometry(QtCore.QRect(650, 270, 131, 51))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.encryptButton.setFont(font)
        self.encryptButton.setObjectName("encryptButton")
        
        # Decrypt Button
        self.decryptButton = QtWidgets.QPushButton(self.centralwidget)
        self.decryptButton.setGeometry(QtCore.QRect(650, 320, 131, 51))
        font = QtGui.QFont()
        font.setFamily("Segoe UI Historic")
        font.setPointSize(11)
        self.decryptButton.setFont(font)
        self.decryptButton.setObjectName("decryptButton")
        
        # Generate Key Button
        self.generateKeyButton = QtWidgets.QPushButton(self.centralwidget)
        self.generateKeyButton.setGeometry(QtCore.QRect(90, 270, 131, 51))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.generateKeyButton.setFont(font)
        self.generateKeyButton.setObjectName("generateKeyButton")
        
        # Key Status Label
        self.keyStatusLabel = QtWidgets.QLabel(self.centralwidget)
        self.keyStatusLabel.setGeometry(QtCore.QRect(10, 440, 311, 41))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.keyStatusLabel.setFont(font)
        self.keyStatusLabel.setText("")
        self.keyStatusLabel.setObjectName("keyStatusLabel")
        
        # Encrypted Text Label
        self.encryptedLabel = QtWidgets.QLabel(self.centralwidget)
        self.encryptedLabel.setGeometry(QtCore.QRect(0, 0, 731, 111))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.encryptedLabel.setFont(font)
        self.encryptedLabel.setObjectName("encryptedLabel")
        
        # Decrypted Text Label
        self.decryptedLabel = QtWidgets.QLabel(self.centralwidget)
        self.decryptedLabel.setGeometry(QtCore.QRect(0, 130, 741, 111))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.decryptedLabel.setFont(font)
        self.decryptedLabel.setText("")
        self.decryptedLabel.setObjectName("decryptedLabel")
        
        # Input Line Edit
        self.inputLineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.inputLineEdit.setGeometry(QtCore.QRect(280, 270, 251, 31))
        self.inputLineEdit.setObjectName("inputLineEdit")
        
        # Image Label
        self.imageLabel = QtWidgets.QLabel(self.centralwidget)
        self.imageLabel.setGeometry(QtCore.QRect(280, 330, 251, 231))
        self.imageLabel.setMinimumSize(QtCore.QSize(251, 231))
        self.imageLabel.setText("")
        self.imageLabel.setPixmap(QtGui.QPixmap("assets/deep.jpg"))
        self.imageLabel.setObjectName("imageLabel")
        
        # Browse Button
        self.browseButton = QtWidgets.QPushButton(self.centralwidget)
        self.browseButton.setGeometry(QtCore.QRect(540, 270, 101, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.browseButton.setFont(font)
        self.browseButton.setObjectName("browseButton")
        
        # Thank You Label
        self.thankYouLabel = QtWidgets.QLabel(self.centralwidget)
        self.thankYouLabel.setGeometry(QtCore.QRect(540, 470, 251, 91))
        self.thankYouLabel.setObjectName("thankYouLabel")
        
        # Menu Bar and Status Bar
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 18))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
        # Connect Buttons to Functions
        self.generateKeyButton.clicked.connect(self.generate_keys)
        self.encryptButton.clicked.connect(self.encrypt_message)
        self.decryptButton.clicked.connect(self.decrypt_message)
        self.browseButton.clicked.connect(self.browse_file)
    
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "NTRU Cryptosystem"))
        self.decryptButton.setText(_translate("MainWindow", "Decrypt"))
        self.encryptButton.setText(_translate("MainWindow", "Encrypt"))
        self.generateKeyButton.setText(_translate("MainWindow", "Generate Key"))
        self.encryptedLabel.setText(_translate("MainWindow", "Hello DeepSec listeners! NTRU sign implementation:"))
        self.thankYouLabel.setText(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:11pt;\">Thanks to my student David Gvadzabia </span></p><p><span style=\" font-size:11pt;\">for the help in implementation!</span></p></body></html>"))
        self.browseButton.setText(_translate("MainWindow", "Browse"))
    
    def generate_keys(self):
        """
        Handle the key generation process.
        """
        generate_keys(int(167), int(3), int(128), 'PRIV_KEY_FILE.npz', 'PUB_KEY_FILE.npz')
        self.keyStatusLabel.setText("Keys were successfully generated.")
    
    def encrypt_message(self):
        """
        Handle the encryption process.
        """
        plaintext = self.inputLineEdit.text()
        if not plaintext:
            self.encryptedLabel.setText("Please enter text to encrypt.")
            return
        
        # Write plaintext to sxva.txt
        with open('sxva.txt', 'w') as plaintext_file:
            plaintext_file.write(plaintext)
        
        # Read plaintext from sxva.txt
        with open('sxva.txt', 'rb') as plaintext_file_handle:
            plaintext_content = plaintext_file_handle.read()
        
        # Convert plaintext to bits
        plaintext_bits = np.unpackbits(np.frombuffer(plaintext_content, dtype=np.uint8))
        plaintext_bits = np.trim_zeros(plaintext_bits, 'b')
        
        # Encrypt plaintext
        encrypted_bits = encrypt_message('PUB_KEY_FILE.npz', plaintext_bits, binary_output=True, use_block=False)
        
        # Write ciphertext to masho.txt
        with open('masho.txt', 'wb') as ciphertext_file:
            ciphertext_file.write(np.packbits(encrypted_bits.astype(int)).tobytes())
        
        # Read a preview of ciphertext for display
        ciphertext_preview = ''
        with open('masho.txt', encoding="latin-1") as ciphertext_display:
            ciphertext_preview = ciphertext_display.read(100)
        
        self.encryptedLabel.setText(f"Encrypted word: {ciphertext_preview}")
    
    def decrypt_message(self):
        """
        Handle the decryption process.
        """
        # Read ciphertext from masho.txt using PRIV_KEY_FILE.npz
        with open('PRIV_KEY_FILE.npz', 'rb') as private_key_file_handle:
            with open('masho.txt', 'rb') as ciphertext_file:
                ciphertext_content = ciphertext_file.read()
        
        # Convert ciphertext to bits
        ciphertext_bits = np.unpackbits(np.frombuffer(ciphertext_content, dtype=np.uint8))
        ciphertext_bits = np.trim_zeros(ciphertext_bits, 'b')
        
        # Decrypt ciphertext
        decrypted_bits = decrypt_message('PRIV_KEY_FILE.npz', ciphertext_bits, binary_input=True, use_block=False)
        
        # Write decrypted bits to hikaru.txt
        with open('hikaru.txt', 'wb') as decrypted_file:
            decrypted_file.write(np.packbits(decrypted_bits.astype(int)).tobytes())
        
        # Read a preview of decrypted text for display
        decrypted_text = ''
        with open('hikaru.txt', 'r') as decrypted_content_file:
            decrypted_text = decrypted_content_file.read(100)
        
        self.decryptedLabel.setText(f"Decrypted word: {decrypted_text}")
    
    def browse_file(self):
        """
        Handle the file browsing and encryption process.
        """
        filename, _ = QFileDialog.getOpenFileName()
        if not filename:
            return
        
        print(f"Selected file: {filename}")
        
        # Read selected file
        with open(filename, "rb") as selected_file_handle:
            file_content = selected_file_handle.read()
        
        print(f"File content (first line): {file_content}")
        
        # Convert file content to bits
        file_bits = np.unpackbits(np.frombuffer(file_content, dtype=np.uint8))
        file_bits = np.trim_zeros(file_bits, 'b')
        
        # Encrypt file content
        encrypted_bits = encrypt_message('PUB_KEY_FILE.npz', file_bits, binary_output=True, use_block=False)
        
        # Write ciphertext to masho.txt
        with open('masho.txt', 'wb') as ciphertext_file:
            ciphertext_file.write(np.packbits(encrypted_bits.astype(int)).tobytes())
        
        # Read a preview of ciphertext for display
        ciphertext_preview = ''
        with open('masho.txt', encoding="latin-1") as ciphertext_display:
            ciphertext_preview = ciphertext_display.read(100)
        
        self.encryptedLabel.setText(f"Encrypted word: {ciphertext_preview}")


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
