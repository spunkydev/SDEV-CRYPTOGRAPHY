import os

from base64 import b64encode, b64decode

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pathlib import Path

class SDEVCrypto:

    def __init__(self) -> None:

        self.prefix: str = '$SDEV;'
        self.extension: str = '.sdev'

    def encrypt_text(
        self,
        data_to_encrypt: str,
        password: str,
        base64: bool = True,
        printable: bool = True
    ) -> str | bytes | None:

        """
        Encrypts the given text using a password-derived key with ChaCha20-Poly1305 and Scrypt for key derivation.
        Args:
            data_to_encrypt (str): The plaintext string to encrypt.
            password (str): The password used for key derivation.
            base64 (bool, optional): If True, returns the encrypted data as a base64-encoded UTF-8 string with a prefix. 
                If False, returns the raw encrypted bytes. Defaults to True.
            printable (bool, optional): If True, prints errors encountered during encryption. Defaults to True.
        Returns:
            str | bytes | None: The encrypted data as a base64-encoded string (with prefix) or raw bytes, 
                or None if encryption fails.
        """

        if not isinstance(password, str):

            if printable:

                print("Password must be a string.")

            return None

        try:

            salt : bytes = os.urandom(16)
            nonce : bytes = os.urandom(12)

            return (self.prefix.encode('utf-8') + b64encode(b'\x01' + salt + nonce + ChaCha20Poly1305(Scrypt(salt=salt, length=32, n=16384, r=8, p=1).derive(password.encode())).encrypt(nonce, data_to_encrypt.encode(), None))).decode('utf-8') if base64 else b'\x01' + salt + nonce + ChaCha20Poly1305(Scrypt(salt=salt, length=32, n=16384, r=8, p=1).derive(password.encode())).encrypt(nonce, data_to_encrypt.encode(), None)

        except Exception as e:

            if printable:

                print(f"Encryption text error: {e}")

        return None

    def decrypt_text(
        self,
        data_to_decrypt: str | bytes,
        password: str,
        printable: bool = True
    ) -> str | bool:

        """
        Decrypts the given data using a password.
        Args:
            data_to_decrypt (str | bytes): The data to decrypt. Can be a string or bytes.
            password (str): The password used for decryption.
            printable (bool, optional): If True, prints error messages. Defaults to True.
        Returns:
            str | False: The decrypted text as a string if successful, or None if decryption fails.
        Notes:
            - The function expects the data to be in a specific format, possibly with a prefix and base64 encoding.
            - Uses Scrypt for key derivation and ChaCha20Poly1305 for decryption.
            - If the password is incorrect or the data is corrupted, returns None and optionally prints an error message.
        """

        if not isinstance(password, str):

            if printable:

                print("Password must be a string.")

            return None

        data_to_decrypt : str | bytes = data_to_decrypt.encode('utf-8') if isinstance(data_to_decrypt, str) else data_to_decrypt

        try:

            if data_to_decrypt.lstrip().startswith(self.prefix.encode('utf-8')):

                data_to_decrypt : bytes = b64decode(data_to_decrypt.strip()[len(self.prefix):])

            if data_to_decrypt.startswith(b'\x01') and len(data_to_decrypt) > 29:

                return ChaCha20Poly1305(Scrypt(salt=data_to_decrypt[1:17], length=32, n=16384, r=8, p=1).derive(password.encode())).decrypt(data_to_decrypt[17:29], data_to_decrypt[29:], None).decode('utf-8')

        except InvalidTag:

            if printable:

                print("Invalid tag, that's mean password is wrong or file have been corrupted, decryption failed.")

        except Exception as e:

            if printable:

                print(f"Decryption text error: {e}")

        return None

    def encrypt_file(
        self,
        filepath_to_encrypt: str | Path,
        password: str,
        add_extension: bool = True,
        printable: bool = True,
        special_filepath_output: str | Path = None,
        delete_initial_file: bool = True
    ) -> bool:

        """
        Encrypts a file using AES-GCM with a key derived from the provided password.
        Args:
            filepath_to_encrypt (str | Path): Path to the file to be encrypted.
            password (str): Password used to derive the encryption key.
            add_extension (bool, optional): Whether to add a custom extension to the output file. Defaults to True.
            printable (bool, optional): If True, prints status and error messages to the console. Defaults to True.
            special_filepath_output (str | Path, optional): Custom output file path. If None, uses the input file path with extension. Defaults to None.
            delete_initial_file (bool, optional): If True, deletes the original file after encryption. Defaults to True.
        Returns:
            bool: True if encryption was successful, False otherwise.
        Notes:
            - The function writes a prefix, salt, and IV to the output file before the encrypted data.
            - Uses PBKDF2HMAC with SHA256 for key derivation and AES-GCM for encryption.
            - Handles large files by processing them in chunks.
            - If the output file already exists, writes to a temporary file and renames it after encryption.
            - Catches and prints exceptions if printable is True.
        """

        if not isinstance(password, str):

            if printable:

                print("Password must be a string.")

            return False

        try:

            if not os.path.exists(filepath_to_encrypt):

                if printable:

                    print(f"File {str(filepath_to_encrypt)} not found, encryption aborted.")

                return False

            if os.path.getsize(filepath_to_encrypt) == 0:

                if printable:

                    print(f"File {str(filepath_to_encrypt)} is empty, encryption aborted.")

                return False

            out_path : str | Path = special_filepath_output if special_filepath_output else str(filepath_to_encrypt) + self.extension if add_extension else filepath_to_encrypt
            work_path : str | Path = out_path if not os.path.exists(out_path) else out_path + ".tmp"

            salt : bytes = os.urandom(16)
            iv : bytes = os.urandom(12)

            encryptor = Cipher(
                algorithms.AES(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend()).derive(password.encode())),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            with open(filepath_to_encrypt, 'rb') as f_in, open(work_path, 'wb') as f_out:

                f_out.write(self.prefix.encode())
                f_out.write(salt)
                f_out.write(iv)

                chunk_size : int = 1024 * 1024 

                while True:

                    chunk : bytes = f_in.read(chunk_size)

                    if not chunk:

                        break

                    f_out.write(encryptor.update(chunk))

                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag)

            if delete_initial_file:

                try:
                    os.remove(filepath_to_encrypt)
                except:
                    pass

            try:
                os.rename(work_path, out_path)
            except:
                pass

            return True

        except Exception as e:

            if printable:

                print(f"Encryption file error: {e}")

            return False

    def decrypt_file(
        self,
        filepath_to_decrypt: str,
        password: str,
        printable: bool = True,
        special_filepath_output: str = None,
        delete_initial_file: bool = True
    ) -> bool:

        try:

            if not os.path.exists(filepath_to_decrypt):

                if printable:

                    print(f"File {filepath_to_decrypt} not found, decryption aborted.")

                return False

            if os.path.getsize(filepath_to_decrypt) == 0:

                if printable:

                    print(f"File {str(filepath_to_decrypt)} is empty, decryption aborted.")

                return False

            out_path : str | Path = special_filepath_output if special_filepath_output else (filepath_to_decrypt[:-len(self.extension)] if filepath_to_decrypt.endswith(self.extension) else filepath_to_decrypt)
            work_path : str | Path = out_path if not os.path.exists(out_path) else out_path + ".tmp"

            with open(filepath_to_decrypt, 'rb') as f_in:

                prefix : str = f_in.read(len(self.prefix)).decode()

                if prefix != self.prefix:

                    if printable:

                        print(f"File {filepath_to_decrypt} is not a valid SDEV file, decryption aborted.")

                    return False

                salt : bytes = f_in.read(16)
                iv : bytes = f_in.read(12)

                f_in.seek(-16, os.SEEK_END)
                tag_offset : int = f_in.tell()
                tag : bytes = f_in.read(16)

                decryptor = Cipher(algorithms.AES(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend()).derive(password.encode())), modes.GCM(iv, tag), backend=default_backend()).decryptor()

                with open(work_path, 'wb') as f_out:

                    f_in.seek(len(self.prefix) + 16 + 12)

                    chunk_size : int = 1024 * 1024  # 1 MiB

                    while f_in.tell() < tag_offset:

                        to_read = min(chunk_size, tag_offset - f_in.tell())
                        chunk = f_in.read(to_read)
                        f_out.write(decryptor.update(chunk))

                    f_out.write(decryptor.finalize())

            if delete_initial_file:

                try:
                    os.remove(filepath_to_decrypt)
                except:
                    pass

            try:
                os.rename(work_path, out_path)
            except:
                pass

            return True

        except Exception as e:

            if printable:

                print(f"Decryption error: {e}")

            return False

################
# Example usage
################

# 1) Encrypting a text:

import time

start_enc = time.time()
password = "MySyperSecretPassword&é$*"

data = SDEVCrypto().encrypt_text("This is a test text to encrypt with a password.", password)

print(f"Encrypted text: {data}")

end_enc = time.time()

print(f"Encryption successful in {end_enc - start_enc:.2f} seconds")

time.sleep(5) # To manually check that the text is encrypted.

# 2) Decrypting a text:	

start_enc = time.time()

result = SDEVCrypto().decrypt_text(data, password)

end_enc = time.time()

print(f"Decrypted text: {result}")
print(f"Decryption successful in {end_enc - start_enc:.2f} seconds")

# 3) Encrypting a file:	

start_enc = time.time()

SDEVCrypto().encrypt_file("exemple.txt", "MyVerySyperSecretPassword%^$*")

end_enc = time.time()

print(f"Encryption successful in {end_enc - start_enc:.2f} seconds")

time.sleep(5) # To manually check that the file is encrypted.

# 4) Decrypting a file:	

start_dec = time.time()

SDEVCrypto().decrypt_file(
    "exemple.txt.sdev",
    "MyVerySyperSecretPassword%^$*",
)

end_dec = time.time()

print(f"Decryption successful in {end_dec - start_dec:.2f} seconds")