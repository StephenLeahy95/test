import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def hashed_passphrase(password: str) -> bytes:
    salt = os.urandom(16)

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

    
    password_bytes =  password.encode("utf-8")
    hashed_passphrase = kdf.derive(password_bytes)

    print("Algorithm: Scrypt")
    print("Salt: " + salt.hex())
    print("Length: 32")
    print("n: 2**14")
    print("r: 8")
    print("p: 1")
    print("Hashed passphrase: " + hashed_passphrase.hex())

    return salt + hashed_passphrase

def password_check(hashed_passphrase: bytes, password: str) -> bool:
    salt = hashed_passphrase[:16]
    password_hash = hashed_passphrase[16:]

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

    try: 
        kdf.verify(password.encode("utf-8"), password_hash)
        return True
    except Exception:
        return False