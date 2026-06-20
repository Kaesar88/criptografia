# Método Caso III: CypherShop - Forense criptográfico en un marketplace de e-commerce
**Asignatura:** Criptografía  
**Universidad:** Mundae 

---

## Descripción del caso

CypherShop S.L. es un marketplace de electrónica de segunda mano con 380.000 usuarios. En abril de 2026 reciben un informe de HackerOne que revela cuatro vulnerabilidades críticas en su módulo de cifrado y autenticación. Este repositorio contiene el análisis forense, las pruebas de concepto y la versión corregida del módulo (`cypherShop_crypto_fixed.py`), cumpliendo con los requisitos del método caso.

---

## Requisitos e instalación

El código está escrito en Python 3.9+ y requiere las siguientes librerías:

- `pycryptodome`
- `PyJWT`
- `argon2-cffi`
- `cryptography` (para la generación de claves Ed25519 en el fix)

Instala todas las dependencias con:

```bash
pip install pycryptodome PyJWT argon2-cffi cryptography
