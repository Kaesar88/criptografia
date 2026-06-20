import random

def generar_token_session():
    random.seed(42)
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(16))

print("Ejecutando generar_token_session() 10 veces consecutivas:")
for i in range(10):
    print(f"{i+1}: {generar_token_session()}")
