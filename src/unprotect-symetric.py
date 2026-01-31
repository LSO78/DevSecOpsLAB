from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA1
from Crypto.Util.Padding import unpad
import sys

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

def integrity_protection(iv :bytes, ki: bytes, salt: bytes, encrypt_file: bytes) -> bytes :
    hmac_object = HMAC.new(ki, digestmod=SHA1)
    hmac_object.update(iv)
    hmac_object.update(salt)
    hmac_object.update(encrypt_file)
    return hmac_object.digest()

def verify_hmac(iv :bytes, ki: bytes, salt: bytes, encrypt_file: bytes, file_in_hmac: bytes) -> bool :
    new_hmac = integrity_protection(iv, ki, salt, encrypt_file)
    if new_hmac != file_in_hmac :
        raise ValueError("[ERROR] Contrôle d'intégrité echoué. Les HMAC ne correspondent pas")
    return True

def file_decryption(Kc: bytes, iv: bytes, data: bytes) -> bytes:
    cipher_object = AES.new(Kc, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher_object.decrypt(data)
    
    try:
        # Suppression du padding PKCS#7
        decrypted_data = unpad(decrypted_data, AES.block_size)
    except PaddingError:
        raise ValueError("[ERROR] Le padding est invalide. Les données sont corrompues ou le mot de passe est incorrect.")
    
    return decrypted_data

def write_data_file(filename: str, decrypted_data: bytes) :
    with open(filename, "wb") as f :
        f.write(decrypted_data)

def get_data(file_in: str) :
    with open(file_in, "rb") as myfile :
        iv = myfile.read(16)
        salt = myfile.read(8)
        data_hmac = myfile.read()
        encrypt_data = data_hmac[:-20]
        hmac = data_hmac[-20:]
    return iv, salt, encrypt_data, hmac

def unprotect_file(file_in: str, file_out: str):
    try:
        check_arguments(password, file_in, file_out)
    except Exception as e:
        print(e)
        sys.exit(1)
    iv, salt, encrypt_data, fil_in_hmac = get_data(file_in)
    km = kdf(password, salt, 32)
    ki = ki_generator(km)
    kc = kc_generator(km)
    try:
        verify_hmac(iv, ki, salt, encrypt_data, fil_in_hmac)
        print("HMAC identique, vérification réussie")
    except ValueError as e:
        print(e)
        sys.exit(1)
    try:
        decrypt_data = file_decryption(kc, iv, encrypt_data)
    except ValueError as e:
        print("[ERROR] Mot de passe incorrect ou données corrompues.")
        sys.exit(1)
    write_data_file(file_out, decrypt_data)
    print(f"Fichier déchiffré avec succès -> {file_out}")

unprotect_file(file_in, file_out)
