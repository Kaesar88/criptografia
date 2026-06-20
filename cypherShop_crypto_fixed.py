"""
cypherShop_crypto_fixed.py

Version corregida del modulo de cifrado y autenticacion de CypherShop.
Cada funcion mantiene la misma firma que la version original para que
el resto de la aplicacion (vistas de Django, tests, etc.) no tenga que
cambiar, pero la implementacion interna usa primitivas criptograficas
seguras en lugar de las que provocaron el incidente.

Dependencias: pycryptodome, PyJWT, argon2-cffi
    pip install pycryptodome PyJWT argon2-cffi
"""

import os
import secrets

from Crypto.Cipher import AES
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# La clave simetrica de la aplicacion debe cargarse desde una variable de
# entorno o un gestor de secretos, nunca dejarse embebida en el codigo
# fuente como ocurria en la version original. Aqui se simula esa carga.
CLAVE_AES = os.environ.get("CYPHERSHOP_AES_KEY", os.urandom(32))  # AES-256 -> 32 bytes

# El par de claves de firma de los tokens de sesion tampoco debe vivir en
# el repositorio. En produccion se generaria una sola vez y se guardaria
# en un almacen de secretos; aqui se genera al cargar el modulo solo para
# que el fichero sea ejecutable de forma autocontenida.
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

_clave_privada_jwt = Ed25519PrivateKey.generate()
_clave_publica_jwt = _clave_privada_jwt.public_key()

_pem_privada = _clave_privada_jwt.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
_pem_publica = _clave_publica_jwt.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def generar_token_sesion() -> str:
    """
    Genera un token de sesion impredecible.

    Fix: la version original usaba el modulo 'random' con una semilla fija
    (random.seed(42)), lo que convierte la secuencia de numeros en algo
    completamente predecible para cualquiera que conozca o adivine esa
    semilla: el generador no esta pensado para usos criptograficos.

    Se sustituye por 'secrets', el modulo de la libreria estandar de Python
    pensado especificamente para generar valores con fines de seguridad
    (tokens, contrasenas temporales, claves), que se apoya en la fuente de
    aleatoriedad del sistema operativo en lugar de en un algoritmo
    determinista con estado interno previsible.
    """
    return secrets.token_hex(16)  # 16 bytes -> 32 caracteres hexadecimales


def cifrar_catalogo(texto_plano: bytes) -> bytes:
    """
    Cifra un bloque de datos del catalogo de productos.

    Fix: la version original usaba AES en modo ECB, que cifra cada bloque
    de 16 bytes de forma totalmente independiente: si dos bloques de texto
    en claro son iguales, el bloque de texto cifrado resultante tambien es
    igual, lo que filtra informacion sobre la estructura y el contenido
    repetido de los datos sin necesidad de romper la clave.

    Se sustituye por AES en modo GCM, que es un modo de cifrado autenticado:
    además de ocultar el contenido, genera un codigo de autenticacion (tag)
    que permite detectar si el texto cifrado ha sido modificado, y usa un
    vector de inicializacion (nonce) aleatorio distinto en cada operacion,
    de forma que cifrar el mismo contenido dos veces produce resultados
    distintos. El nonce no es secreto: se almacena junto al texto cifrado
    y se necesita para poder descifrar.
    """
    nonce = os.urandom(12)  # 12 bytes es el tamaño de nonce recomendado para GCM
    cipher = AES.new(CLAVE_AES, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(texto_plano)
    # Se devuelve nonce + tag + ciphertext concatenados para que el
    # descifrado disponga de todo lo necesario en un único valor.
    return nonce + tag + ciphertext


def descifrar_catalogo(datos_cifrados: bytes) -> bytes:
    """Funcion complementaria de descifrado, necesaria para poder
    verificar que el fix de cifrar_catalogo() funciona correctamente."""
    nonce = datos_cifrados[:12]
    tag = datos_cifrados[12:28]
    ciphertext = datos_cifrados[28:]
    cipher = AES.new(CLAVE_AES, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


_password_hasher = PasswordHasher()


def hash_contrasena(password: str) -> str:
    """
    Genera el hash de una contraseña para almacenarla en base de datos.

    Fix: la version original usaba MD5, una funcion de hash diseñada para
    verificar integridad de datos, no para proteger contraseñas: es muy
    rapida de calcular (lo que facilita probar millones de contraseñas
    por segundo) y no incorpora un valor aleatorio (salt), por lo que dos
    usuarios con la misma contraseña obtienen siempre el mismo hash, lo
    que además permite usar tablas precalculadas (rainbow tables) para
    revertirlo casi instantaneamente.

    Se sustituye por Argon2id, una funcion de derivacion de claves
    diseñada especificamente para contraseñas: es deliberadamente lenta y
    costosa en memoria (lo que dificulta los ataques de fuerza bruta a
    gran escala, incluso con hardware especializado) y genera un salt
    aleatorio distinto en cada llamada, que queda incluido en el propio
    resultado, por lo que la misma contraseña nunca produce el mismo hash
    dos veces.
    """
    return _password_hasher.hash(password)


def verificar_contrasena(hash_almacenado: str, password_introducida: str) -> bool:
    """Funcion complementaria de verificacion, necesaria para comprobar
    que el fix de hash_contrasena() sigue permitiendo iniciar sesion."""
    try:
        _password_hasher.verify(hash_almacenado, password_introducida)
        return True
    except VerifyMismatchError:
        return False


def crear_token_usuario(user_id: int, admin: bool = False) -> str:
    """
    Crea el token de sesion (JWT) de un usuario autenticado.

    Fix: la version original generaba el token con el algoritmo 'none',
    es decir, sin ninguna firma digital. Un JWT sin firma es solo texto
    codificado en base64: cualquiera puede decodificar el payload,
    modificarlo (por ejemplo, cambiar "admin": false a "admin": true) y
    volver a codificarlo, sin que el servidor tenga ninguna forma de
    detectar la manipulacion.

    Se sustituye por una firma digital con EdDSA (curva Ed25519): el
    servidor firma el payload con su clave privada, y cualquier
    modificacion del contenido invalida la firma al verificarla con la
    clave publica correspondiente. Sin acceso a la clave privada, es
    matematicamente inviable generar una firma valida para un payload
    modificado.
    """
    payload = {"user_id": user_id, "admin": admin}
    return jwt.encode(payload, _pem_privada, algorithm="EdDSA")


def verificar_token_usuario(token: str) -> dict:
    """Funcion complementaria de verificacion, necesaria para comprobar
    que el fix de crear_token_usuario() rechaza tokens no firmados o
    modificados."""
    return jwt.decode(token, _pem_publica, algorithms=["EdDSA"])


if __name__ == "__main__":
    print("=== Fix 1: generar_token_sesion() ===")
    tokens = [generar_token_sesion() for _ in range(5)]
    for i, t in enumerate(tokens, start=1):
        print(f"  token {i}: {t}")
    print(f"  Todos distintos entre si: {len(set(tokens)) == len(tokens)}")
    print()

    print("=== Fix 2: cifrar_catalogo() / descifrar_catalogo() ===")
    texto = b"PRECIO: 99.99   PRECIO: 99.99   "
    c1 = cifrar_catalogo(texto)
    c2 = cifrar_catalogo(texto)
    print(f"  Texto original: {texto}")
    print(f"  Cifrado 1 (hex): {c1.hex()}")
    print(f"  Cifrado 2 (hex): {c2.hex()}")
    print(f"  ¿Son iguales los dos cifrados del mismo texto?: {c1 == c2}")
    descifrado = descifrar_catalogo(c1)
    print(f"  Descifrado correcto: {descifrado == texto}")
    print()

    print("=== Fix 3: hash_contrasena() / verificar_contrasena() ===")
    h1 = hash_contrasena("password123")
    h2 = hash_contrasena("password123")
    print(f"  hash 1: {h1}")
    print(f"  hash 2: {h2}")
    print(f"  ¿Son iguales los dos hashes de la misma contraseña?: {h1 == h2}")
    print(f"  Verificación con contraseña correcta: {verificar_contrasena(h1, 'password123')}")
    print(f"  Verificación con contraseña incorrecta: {verificar_contrasena(h1, 'otraclave')}")
    print()

    print("=== Fix 4: crear_token_usuario() / verificar_token_usuario() ===")
    token = crear_token_usuario(42, admin=False)
    print(f"  Token generado: {token}")
    payload = verificar_token_usuario(token)
    print(f"  Payload verificado correctamente: {payload}")

    # Intento de manipulacion: tomamos el token y cambiamos admin a True
    # directamente en el payload, sin volver a firmarlo con la clave privada.
    import base64
    import json

    header_b64, payload_b64, firma_b64 = token.split(".")
    payload_manipulado = json.loads(
        base64.urlsafe_b64decode(payload_b64 + "==")
    )
    payload_manipulado["admin"] = True
    payload_manipulado_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload_manipulado).encode())
        .rstrip(b"=")
        .decode()
    )
    token_manipulado = f"{header_b64}.{payload_manipulado_b64}.{firma_b64}"
    print(f"  Token manipulado (admin->true sin re-firmar): {token_manipulado}")
    try:
        verificar_token_usuario(token_manipulado)
        print("  El token manipulado fue aceptado (ESTO NO DEBERIA OCURRIR)")
    except jwt.InvalidSignatureError:
        print("  El token manipulado fue RECHAZADO: firma invalida detectada.")
