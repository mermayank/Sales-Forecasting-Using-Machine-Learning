import hashlib
import secrets
import json
import os
import base64
import io
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.http import MediaIoBaseDownload
from google.auth.transport.requests import Request
from web3 import Web3, utils
from miniproject import settings
from .utils import *

# Constants
BLOCKCHAIN_URL = "https://sepolia.infura.io/v3/ea5f42a95d304c5c9225aa829a243d67"  # Replace with your Infura testnet URL
CONTRACT_ABI_PATH = "mp/newabi.json"  # Path to your contract ABI file
CONTRACT_ADDRESS = "0x05d016Bb8AeDc3fc22247940133c48320bEd53c0"  # Replace with your deployed contract address
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_PATH = os.path.join(settings.BASE_DIR, 'credentials.json')  # Replace with the path to your credentials.json file

# Connect to Ethereum testnet
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

# Check Blockchain Connection
if not w3.is_connected():
    raise Exception("Failed to connect to Ethereum network!")

# Load Smart Contract ABI
with open(CONTRACT_ABI_PATH, "r") as abi_file:
    CONTRACT_ABI = json.load(abi_file)

# Helper Functions for Google Drive Integration
def authenticate_google_drive():
    """Authenticate and return the Google Drive API service, forcing manual sign-in each time."""
    if os.path.exists('token.json'):
        os.remove('token.json')
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
    creds = flow.run_local_server(port=8081)
    return build('drive', 'v3', credentials=creds)

def upload_file_to_drive(file_path, service):
    """Uploads the encrypted file to Google Drive and returns the file's shareable link."""
    file_metadata = {'name': os.path.basename(file_path)}  
    media = MediaIoBaseUpload(io.FileIO(file_path, 'rb'), mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    drive_id = file['id']
    file_link = f"https://drive.google.com/file/d/{drive_id}/view?usp=sharing"
    
    return file_link

def sha256_hash(data):
    """Compute the SHA256 hash of the given data."""
    return hashlib.sha256(data).digest()

# AES Encryption/Decryption Functions
def encrypt_file(file_path, key, nonce):
    cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt_file(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def compute_access_polynomial_coefficients(user_keys, master_key):
    if not user_keys:  # Check if list is empty
        master_key_int = int.from_bytes(master_key, byteorder='big')
        coefficients[0] = (master_key_int) % getPrime(256)
    else:
        n = len(user_keys)
        coefficients = [0] * n
        coefficients[0] = hash(user_keys[0]) % getPrime(256)

        for i in range(1, n):
            beta = hash(user_keys[i]) % getPrime(256)
            coefficients[i] = 1
            for j in range(i - 1, 0, -1):
                coefficients[j] = (coefficients[j - 1] - beta * coefficients[j]) % getPrime(256)
            coefficients[0] = ( coefficients[0] - beta * coefficients[0]) % getPrime(256)
        master_key_int = int.from_bytes(master_key, byteorder='big')
        coefficients[0] = (coefficients[0] + master_key_int) % getPrime(256)
    return coefficients

def evaluate_access_polynomial(coefficients, user_key):
    x = hash(user_key) % getPrime(256)
    result = coefficients[0]
    print(result)
    for i in range(1, len(coefficients)):
        result = (result + coefficients[i] * pow(x, i, getPrime(256))) % getPrime(256)
        print(result)
    return result

# User Registration and Login Functions
def register_user(username, password, name, email, department, subscription_period,pk, contract_address=CONTRACT_ADDRESS):
    contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
    private_key = pk.strip()
    address = w3.eth.account.from_key(private_key).address

    register_user_data = {
        "username": username,
        "password": password,
        "name": name,
        "email": email,
        "department": department,
        "subscriptionPeriod": subscription_period
    }

    tx = contract.functions.registerUser (register_user_data).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address)
    })
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    txn_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
    user_id = contract.functions.getUser (username).call()[0]

    return user_id

def login_user(username, password, pk, contract_address=CONTRACT_ADDRESS):
    contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
    private_key = pk.strip()
    # address = w3.eth.account.from_key(private_key).address
    user_data = contract.functions.getUser(username).call()

    if user_data[1] != username:
        return None, None

    keccak256 = keccak.new(digest_bits=256)
    keccak256.update(password.encode())
    password_hash = keccak256.digest()
    if user_data[2] == password_hash:
        return user_data, private_key
    return None, None

# Classes for Data Owner and User
class DataOwner:
    def __init__(self, private_key, contract_address=CONTRACT_ADDRESS):
        self.private_key = private_key
        self.address = w3.eth.account.from_key(self.private_key).address
        self.contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)

    def upload_file(self, file_path, access_policy):
        file_name = os.path.basename(file_path)
        file_tag = sha256_hash(file_name.encode())

        file_hash = sha256_hash(open(file_path, 'rb').read())
        cipher_key = sha256_hash(file_hash + b"some_other_info")  # Generate secret key
        nonce = get_random_bytes(16)
       
        # Check if file_tag is already present in blockchain
        existing_metadata = self.contract.functions.getFileMetadata(file_tag, file_hash).call()
        if not existing_metadata[0] == "":
            print("File already exists in the blockchain.")
            drive_link = existing_metadata[0]
            owners = existing_metadata[1]
            nonce = existing_metadata[2]
            cipher_key = existing_metadata[3]
            access_policies = existing_metadata[4]
            coeffs = existing_metadata[5]
            req_ids = existing_metadata[6]
            fileHash = existing_metadata[7]
            file_id = existing_metadata[8]
            filename = existing_metadata[9]

            owners.append(self.address)
            access_policies.append(access_policy)

            file_metadata = {
                "fileLink": drive_link,
                "uploaders": owners,
                "iv": nonce,
                "cipherKey": cipher_key,
                "accessPolicy": access_policies,
                "coefficients": coeffs,  
                "request_id": req_ids,     
                "fileHash": fileHash,
                "fileId": file_id,
                "filename": filename 
            }
            #------------------Debug----------------------------
            print("File Metadata: ", file_metadata)

            # Use legacy transaction with explicit gasPrice
            gas_price = w3.eth.gas_price  # Get the current gas price
            # Store file metadata in blockchain
            tx = self.contract.functions.updateFileMetadata(file_tag, file_metadata).build_transaction({
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(self.address),
                'gasPrice': gas_price  # Explicitly set gasPrice
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            print("File metadata updated in blockchain!")
            if file_tag != file_id:
                print("File stored as ", filename)
                return (2, filename)
            else:
                return (1,'')
        else:
            # Create a temporary file for ciphertext
            ciphertext = encrypt_file(file_path, cipher_key, nonce)
            encrypted_file_path = f"{file_path}.enc"
            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(ciphertext)

            # Upload the encrypted file to Google Drive
            service = authenticate_google_drive()
            drive_link = upload_file_to_drive(encrypted_file_path, service)

            owners = [self.address]
            access_policies = [access_policy]        
        
            file_metadata = {
                "fileLink": drive_link,
                "uploaders": owners,
                "iv": nonce,
                "cipherKey": cipher_key,
                "accessPolicy": access_policies,
                "coefficients": b"",  # Initially empty
                "request_id": [],     # Initially empty
                "fileHash": file_hash,
                "fileId": file_tag,
                "filename": file_name
            }
            #------------------Debug----------------------------
            print("File Metadata: ", file_metadata)

            # Use legacy transaction with explicit gasPrice
            gas_price = w3.eth.gas_price  # Get the current gas price
            # Store file metadata in blockchain
            tx = self.contract.functions.uploadFileMetadata(file_tag, file_metadata).build_transaction({
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(self.address),
                'gasPrice': gas_price  # Explicitly set gasPrice
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            print("File uploaded and metadata stored in blockchain!")
            return (3,'')

    def display_req(self, file_name):
        details = []

        file_tag = sha256_hash(file_name.encode())
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        if not file_metadata[0]:  # Check if file exists
            return ["File Not Found"]

        # Extract file details
        file_link = file_metadata[0]  # URL to the encrypted file
        uploaders = file_metadata[1]  # List of uploaders
        iv = file_metadata[2]         # Initialization vector for AES decryption
        cipher_key = file_metadata[3] # AES key for decryption
        access_policies = file_metadata[4]  # Access policy
        coefficients = file_metadata[5]   # Coefficients for access control
        request_ids = file_metadata[6]    # Registered requests

        access_policy = access_policies[uploaders.index(self.address)]
        for i, req_id in enumerate(request_ids):
            req = self.contract.functions.getRequest(req_id).call()
            if req == b'\x00':
                continue
            req_data = req.decode().split('\\')
            print(req_data)
            username = req_data[1]
            user_data = self.contract.functions.getUser(username).call()

            # Check user attributes against access policy
            user_attributes = self.get_user_attributes(user_data)
            #print("User : ",user_attributes, " , ap: ",access_policy)
            if not self.check_access_policy(access_policy, user_attributes):
                details.append((i, req_id, username, "N"))
            else:
                details.append((i, req_id, username, "Y"))
        print(details)
        return details

    def grant_access(self, file_name, details, username):
        file_tag = sha256_hash(file_name.encode())
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        user_data = self.contract.functions.getUser(username).call()
        user_id = user_data[0]
        
        # Extract file details
        file_link = file_metadata[0]  # URL to the encrypted file
        uploaders = file_metadata[1]  # List of uploaders
        iv = file_metadata[2]         # Initialization vector for AES decryption
        cipher_key = file_metadata[3] # AES key for decryption
        access_policies = file_metadata[4]  # Access policy
        coefficients = file_metadata[5]   # Coefficients for access control
        request_ids = file_metadata[6]    # Registered requests
        fileHash = file_metadata[7]
        file_id = file_metadata[8]
        filename = file_metadata[9]

        user_keys = get_keys(file_tag, user_id)
        user_names = get_users(file_tag, user_id)
        #------------------Debug----------------------------
        print("\n\nInitially keys: ",user_keys, user_names)

        for i, req in enumerate(details):
            print("Req: ",req)
            req_id = req[1]
            if req[3] == "Y":
                subs_key = secrets.token_bytes(32)
                user_keys.append(subs_key)
                user_names.append(req[2])

                res_str = file_name +"\\"+ subs_key.hex() +"\\"+ self.address
                res = res_str.encode()

                nonce = w3.eth.get_transaction_count(self.address)
                base_gas_price = w3.eth.gas_price

                tx = self.contract.functions.grantAccess(req_id, res, 1).build_transaction({
                    'from': self.address,
                    'nonce': nonce,
                    'gasPrice': base_gas_price
                })
                signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
                w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                print(f"Access granted to req {i}.")
            else:
                res = "".encode()
                tx = self.contract.functions.grantAccess(req_id, res, 2).build_transaction({
                    'from': self.address,
                    'nonce': w3.eth.get_transaction_count(self.address)
                })
                signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
                w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                print(f"Access rejected to req {i}.")
            nonce += 1
        coeffs = compute_access_polynomial_coefficients(user_keys, cipher_key)
        coefficients = b''.join(int.to_bytes(coef, 32, 'big') for coef in coeffs)
        metadata = {
                "fileLink": file_link,
                "uploaders": uploaders,
                "iv": iv,
                "cipherKey": cipher_key,
                "accessPolicy": access_policies,
                "coefficients": coefficients,  # Initially empty
                "request_id": request_ids,    # Initially empty
                "fileHash": fileHash,
                "fileId": file_id,
                "filename": filename
            }
        gas_price = w3.eth.gas_price  # Get the current gas price
        tx = self.contract.functions.updateFileMetadata(file_tag, metadata).build_transaction({
            'from': self.address,
            'nonce': w3.eth.get_transaction_count(self.address),
            'gasPrice': gas_price
        })
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        #------------------Debug----------------------------
        print("\nFinally keys: ",user_keys, user_names)
        # Update user keys in blockchain
        add_keys(file_tag, user_id, user_keys, user_names)
        print("User_Keys updated in blockchain!")

    def get_user_attributes(self, user_data):
        user_attributes = {
            "department": user_data[5],
            "subscription_period": user_data[6]
        }
        return user_attributes

    def check_access_policy(self, access_policy, user_attributes):
        policy_pairs = access_policy.split(", ")
        user_attr_dict = {key: value for key, value in user_attributes.items()}

        for pair in policy_pairs:
            attribute, value = pair.split(":")
            attribute = attribute.strip()
            value = value.strip()
            
            if attribute not in user_attr_dict or user_attr_dict[attribute] != value:
                return False
        return True
    
    def display_users(self, file_name, username):
        print("inside display_users")
        file_tag = sha256_hash(file_name.encode())
        user_data = self.contract.functions.getUser(username).call()
        user_id = user_data[0]
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        if not file_metadata[0]:  # Check if file exists
            return ["File Not Found"]

        user_keys = get_keys(file_tag, user_id)
        user_names = get_users(file_tag, user_id)
        print("\n keys, names: ",user_keys, user_names)
        return user_names
    
    def revoke_access(self, file_name, username, to_revoke):
        file_tag = sha256_hash(file_name.encode())
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        user_data = self.contract.functions.getUser(username).call()
        user_id = user_data[0]

        #------------------Debug----------------------------
        print("Filetag: ",file_tag)
        print("UId: ", user_id)

        user_keys = get_keys(file_tag, user_id)
        user_names = get_users(file_tag, user_id)
        print("\nkeys, users: ",user_keys, user_names)

        for u in to_revoke:
            user_addr = self.contract.functions.getUserAddress(u).call()

            idx = user_names.index(u)
            x = user_keys.pop(idx)
            user_names.remove(u)

            req_str = file_name +"\\"+ u +"\\"+ user_addr
            req = req_str.encode()
            req_id = hashlib.sha256(req).digest()

            res = "".encode()
            tx = self.contract.functions.grantAccess(req_id, res, 2).build_transaction({
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(self.address)
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            print(f"Access rejected to user {u}.")

        # Extract file details and update Metadata
        file_link = file_metadata[0]  # URL to the encrypted file
        uploaders = file_metadata[1]  # List of uploaders
        iv = file_metadata[2]         # Initialization vector for AES decryption
        cipher_key = file_metadata[3] # AES key for decryption
        access_policies = file_metadata[4]  # Access policy
        coefficients = file_metadata[5]   # Coefficients for access control
        request_ids = file_metadata[6]    # Registered requests

        coeffs = compute_access_polynomial_coefficients(user_keys, cipher_key)
        coefficients = b''.join(int.to_bytes(coef, 32, 'big') for coef in coeffs)
        metadata = {
                "fileLink": file_link,
                "uploaders": uploaders,
                "iv": iv,
                "cipherKey": cipher_key,
                "accessPolicy": access_policies,
                "coefficients": coefficients,  # Initially empty
                "request_id": request_ids    # Initially empty
            }
        gas_price = w3.eth.gas_price  # Get the current gas price
        tx = self.contract.functions.updateFileMetadata(file_tag, metadata).build_transaction({
            'from': self.address,
            'nonce': w3.eth.get_transaction_count(self.address),
            'gasPrice': gas_price
        })
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print("File Metadata updated in blockchain!")


class User:
    def __init__(self, private_key, contract_address=CONTRACT_ADDRESS):
        self.private_key = private_key
        self.address = w3.eth.account.from_key(private_key).address
        self.contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)

    def request_access(self, file_name, username):
        file_tag = sha256_hash(file_name.encode())
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        if not file_metadata[0]:  # Check if file exists
            print("File not found.")
            return -1

        req_str = file_name +"\\"+ username +"\\"+ self.address
        req = req_str.encode()
        request_id = hashlib.sha256(req).digest()

        try:
            tx = self.contract.functions.requestAccess(file_tag, request_id, req).build_transaction({
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(self.address)
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        except Exception as e:
            return e
        print(f"Access request for file {file_name} registered with request ID {request_id}.")
        return 1

    def download_and_decrypt_file(self, file_name, username):
        file_tag = sha256_hash(file_name.encode())
        file_metadata = self.contract.functions.getFileMetadata(file_tag).call()
        if not file_metadata[0]:  # Check if file exists
            print("File not found.")
            return -1

        req_str = file_name +"\\"+ username +"\\"+ self.address
        req = req_str.encode()
        req_id = hashlib.sha256(req).digest()
        try:
            response = self.contract.functions.getResponse(req_id).call()
            print("Response: ",response)
            print(type(response))
            if response == b'\x00' :
                print("Request under process")
                return 0
            elif response == b'\x02' :
                print("Permission Denied")
                return 2     
            else:
                # Extract file details
                file_link = file_metadata[0]  # URL to the encrypted file
                iv = file_metadata[2]         # Initialization vector for AES decryption
                cipher_key = file_metadata[3] # AES key for decryption
                access_policy = file_metadata[4]  # Access policy
                coefficients = file_metadata[5]   # Coefficients for access control
                #------------------Debug----------------------------
                print("Original ID: ",file_tag)
                downloaded_file = file_name+"_copy"
                with open(downloaded_file, 'wb') as f:
                    f.write(b'')
                if isinstance(file_link, bytes):
                    file_link = file_link.decode()
                
                from_id = file_link[32:].split('/')
                drive_id = from_id[0]   
                service = authenticate_google_drive()
                request = service.files().get_media(fileId=drive_id)
                fh = io.FileIO(downloaded_file, 'wb')
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                    print(f"Download {int(status.progress() * 100)}%.")
                print(f"File downloaded as {downloaded_file}.")
                with open(downloaded_file, "rb") as f:
                    encrypted_data = f.read()

                res_data = response.decode().split('\\')
                #------------------Debug----------------------------
                print(res_data)
                
                # Decrypt the file using AES
                try:
                    cipher = AES.new(cipher_key, AES.MODE_CBC, iv=iv)
                    plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    return
                
                # Save the decrypted file
                downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
                decrypted_file_path = os.path.join(downloads_path, f"{file_name}")
                with open(decrypted_file_path, "wb") as f:
                    f.write(plaintext)
                print(f"File decrypted and saved as {decrypted_file_path}.")
                return 1
        except Exception as e:
            return e
