# SiFT Protocol v1.1

SiFT (Secure File Transfer) Protocol is a secure communication protocol designed to ensure confidentiality, integrity, and authentication during file transfers and remote operations. This project leverages modern cryptographic techniques to protect sensitive data and prevent unauthorized access.

---

## Usage
### 1. Generate ECC Keys
Generate ECC keys for the client and server:
```bash
python ecdh.py
```
### 2. Run the Server
Start the server:
```bash
python server.py
```
### 3. Run the Client
Start the client:
```bash
python client.py
```
## Debugging
Enable debugging by setting `self.DEBUG = True` in the SiFT_MTP, SiFT_LOGIN, and SiFT_CMD classes. This will print detailed logs of the encryption, decryption, and message handling processes.

## Supported Commands

### 1. **File and Directory Operations**
- **`pwd`**: Get the current directory.
- **`ls`**: List files and directories in the current directory.
- **`cd <dir>`**: Change the current directory.
- **`mkd <dir>`**: Create a new directory.
- **`del <file/dir>`**: Delete a file or directory.
- **`help`**: Shows help menu

### 2. **File Upload**
- **`upl <filename> <filesize> <filehash>`**: Upload a file to the server.

### 3. **File Download**
- **`dnl <filename>`**: Download a file from the server.

---

## Requirements

- Python 3.8+
- Libraries:
  - `pycryptodome` for cryptographic operations.

Install dependencies using:
```bash
pip install pycryptodome
```
## Disclaimer
This project is for educational purposes only. While it implements strong cryptographic techniques, it should not be used in production without a thorough security review.

## License
This project is licensed under the MIT License.