from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_contrasena(password):
    """Reemplazo seguro de MD5 usando Argon2id."""
    return ph.hash(password)

def verificar_contrasena(hash_almacenado, password):
    """Verifica si la contraseña coincide con el hash almacenado."""
    try:
        ph.verify(hash_almacenado, password)
        return True
    except VerifyMismatchError:
        return False

# Demostración
password = 'password123'
print("=== 3 hashes de la misma contraseña ===")
for i in range(3):
    print(f"Hash {i+1}: {hash_contrasena(password)}")

print("\n=== Verificación ===")
h = hash_contrasena(password)
print(f"Hash generado: {h}")
print(f"Verificación con contraseña correcta: {verificar_contrasena(h, password)}")
print(f"Verificación con contraseña incorrecta: {verificar_contrasena(h, 'wrong')}")
