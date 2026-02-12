from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256, SHA1
import sys
import os

file_in = sys.argv[1]
file_out = sys.argv[2]

password = "chiffrementsymetrique"

def check_arguments(password: str, file_in: str, file_out: str):
    if not password:
        raise ValueError("[ERROR] Password ne peut pas être nul")
    if not file_in:
        raise ValueError("[ERROR] file_in ne peut pas être nul")
    if not file_out:
        raise ValueError("[ERROR] file_out ne peut pas être nul")
    try:
        with open(file_in, "rb"):
            pass
    except FileNotFoundError:
        raise FileNotFoundError(f"[ERROR] '{file_in}' n'existe pas")
    except Exception as e:
        raise IOError(f"[ERROR] Impossible d'accéder à '{file_in}': {e}")

def kdf(password: str, salt: bytes, key_length: int) -> bytes :
    return scrypt(password.encode(), salt, key_length, N=2**14, r=8, p=1)

def kc_generator(km: bytes) -> bytes :
    ho = SHA256.new()
    ho.update(km)
    ho.update((0).to_bytes())
    return ho.digest()

def ki_generator(km: bytes) -> bytes :
    ho = SHA1.new()
    ho.update(km)
    ho.update((1).to_bytes())
    return ho.digest()

def optimized_protect(kc: bytes, ki: bytes, iv: bytes, file_in: str, file_out: str, salt: bytes) :
    cipher_object = AES.new(kc, AES.MODE_CBC, iv=iv)
    hmac_object = HMAC.new(ki, digestmod=SHA1)
    hmac_object.update(iv)
    hmac_object.update(salt)

    with open(file_in, "rb") as f1 :
        data = f1.read(AES.block_size)

        with open(file_out, "wb") as f2 :
            f2.write(iv)
            f2.write(salt)

            while len(data) > 0 :

                if len(data) < AES.block_size :
                    data = pad(data, AES.block_size)

                encrypted_data = cipher_object.encrypt(data)
                hmac_object.update(encrypted_data)
                f2.write(encrypted_data)
                data = f1.read(AES.block_size)

            if os.path.getsize(file_in) % AES.block_size == 0:
                padding_block = pad(b"", AES.block_size)
                encrypted_data = cipher_object.encrypt(padding_block)
                hmac_object.update(encrypted_data)
                f2.write(encrypted_data)
                
            f2.write(hmac_object.digest())

def protect_file(password: str, file_in: str, file_out: str) :
    try:
        check_arguments(password, file_in, file_out)
    except Exception as e:
        print(e)
        sys.exit(1)
    salt = b'\x4d\xd4\x03\x73\x9d\x64\xfc\x71'
    km = kdf(password, salt, 32)
    ki = ki_generator(km)
    kc = kc_generator(km)
    iv = b'\xd8\x58\x9c\x27\x91\xcc\x25\x8d\x91\x27\xc1\xa9\xd2\x9e\x5b\xb9'
    optimized_protect(kc, ki, iv, file_in, file_out, salt)
    print(f"Fichier chiffré avec succès -> {file_out}")

protect_file(password, file_in, file_out)