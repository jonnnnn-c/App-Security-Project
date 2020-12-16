import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def generate_key(mode):
    if mode == 1:
        pass_from_user = input("Enter a password to encrypt the config file: ")
    else:
        pass_from_user = input("Enter config file password to start program: ")

    password = pass_from_user.encode()
    mysalt = b'q\xe3Q5\x8c\x19~\x17\xcb\x88\xc6A\xb8j\xb4\x85'
    # generated using os.urandom(16)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256,
                     length=32,
                     salt=mysalt,
                     iterations=100000,
                     backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)

    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    return decrypted_data


# Used to encrypt the file
if __name__ == '__main__':
    key = generate_key(1)
    print('Encrypting config.json successful!')
    encrypt('etc/settings/config.json', key)
