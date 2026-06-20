# ejercicio3.py
from Crypto.Cipher import AES
import os

# Clave aleatoria de 16 bytes (AES-128)
KEY = os.urandom(16)

# Texto plano de 32 bytes = 2 bloques IDÉNTICOS
plaintext = b'PRECIO: 99.99   PRECIO: 99.99   '

print("Texto plano (hex):    ", plaintext.hex())
print("Bloque 1 (hex):       ", plaintext[:16].hex())
print("Bloque 2 (hex):       ", plaintext[16:].hex())
print("¿Bloque1 == Bloque2? ", plaintext[:16] == plaintext[16:])
print()

# ---------- 1. AES-ECB ----------
cipher_ecb = AES.new(KEY, AES.MODE_ECB)
ciphertext_ecb = cipher_ecb.encrypt(plaintext)

print("=== AES-ECB ===")
print("Ciphertext completo (hex):", ciphertext_ecb.hex())
print("Bloque cifrado 1 (hex):   ", ciphertext_ecb[:16].hex())
print("Bloque cifrado 2 (hex):   ", ciphertext_ecb[16:].hex())
print("¿BloqCif1 == BloqCif2?   ", ciphertext_ecb[:16] == ciphertext_ecb[16:])
print()

# ---------- 2. AES-GCM (con IV aleatorio) ----------
iv = os.urandom(12)
cipher_gcm = AES.new(KEY, AES.MODE_GCM, nonce=iv)
ciphertext_gcm, tag = cipher_gcm.encrypt_and_digest(plaintext)

print("=== AES-GCM ===")
print("IV (hex):               ", iv.hex())
print("Ciphertext completo (hex):", ciphertext_gcm.hex())
print("Tag (hex):              ", tag.hex())
print("Bloque cifrado 1 (hex):   ", ciphertext_gcm[:16].hex())
print("Bloque cifrado 2 (hex):   ", ciphertext_gcm[16:].hex())
print("¿BloqCif1 == BloqCif2?   ", ciphertext_gcm[:16] == ciphertext_gcm[16:])
