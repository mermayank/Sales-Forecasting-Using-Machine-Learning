# secure-cloud-file-sharing-project-using-Blockchain-and-AttributeBased-Encryption-ABE
# 🔐 Secure Cloud File Sharing using Blockchain & Attribute-Based Encryption

This project implements a secure, decentralized cloud-based file sharing framework using **Django**, **Ethereum smart contracts**, **Google Drive**, and **Attribute-Based Encryption (ABE)**. It allows file owners to securely upload encrypted files, manage access control via blockchain, and revoke access instantly using access polynomials.

## 📌 Features

- 🔑 **User Registration & Login** (via Ethereum private key)
- 🧾 **Fine-grained Access Control** using attribute-based encryption
- ☁️ **File Encryption & Upload** to Google Drive
- 📃 **Access Requests & Granting** handled on the Ethereum blockchain
- 🔄 **Access Revocation** without communication overhead to other users
- 🧮 **Polynomial-based Key Distribution** for fast and secure key sharing

## 🏗️ Architecture

- **Frontend/Backend**: Django Web Framework (Python)
- **Cloud Storage**: Google Drive API for file storage
- **Blockchain**: Ethereum (Sepolia testnet) using smart contracts
- **Encryption**: AES (CBC), Hashing (SHA256/Keccak), Polynomial-based key distribution

## 🧠 Based On

Research Paper:  
**"Secure cloud file sharing scheme using blockchain and attribute-based encryption"**  
📄 [Elsevier - Computer Standards & Interfaces, 2024](https://doi.org/10.1016/j.csi.2023.103745)

## 🗃️ Folder Structure

├── models.py # Django models for users, files, subscriptions
├── views.py # Handles logic for uploads, requests, access control
├── new1.py # Core blockchain and encryption logic
├── urls.py # URL routing for Django
├── newabi.json # ABI for the deployed smart contract
├── newsol1.sol # Solidity smart contract (not visible here)
└── templates/ # HTML templates for login, upload, etc.


## ⚙️ How it Works

1. **Register/Login**: User signs up with credentials and Ethereum private key.
2. **Upload File**: Data owner encrypts the file and uploads it to Google Drive.
3. **Access Control**: Metadata (including polynomial coefficients and policies) is stored on the Ethereum blockchain.
4. **Request Access**: Users request access; data owner grants it based on attributes.
5. **Decrypt File**: User decrypts the file if their attributes satisfy the access policy.
6. **Revoke Access**: Data owner updates access polynomial, instantly revoking access for the user.

## 🧪 Technologies Used

- Python, Django
- Web3.py, Solidity, Ethereum (Sepolia)
- AES (PyCryptodome)
- Google Drive API (OAuth2.0)
- JSON, SHA256, Keccak


## 🛠️ Setup Instructions

1. Clone the repo
2. Create a virtual environment and install dependencies
3. Add your Google Drive API credentials.json to the root directory
4. Deploy the smart contract and update new1.py with:
        -Infura Project URL
        -Contract Address
        -ABI path
5. Run the Django server
