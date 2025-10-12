#!/usr/bin/env python3
"""
decrypt_template.py
Lit capture.json et keyfile.txt dans le dossier courant, déchiffre AES-128-CBC
et affiche le message en clair.

Utilisation:
    python3 decrypt_template.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
from binascii import unhexlify

# --- Variables à compléter ---
JSON_FILE = "<TODO: nom du fichier JSON>" # à compléter
KEYFILE = "<TODO: nom du fichier contenant la clé>" # à compléter

def read_keyfile(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{path} introuvable")
    key = None
    iv = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # accepte formats comme "key:4989..." ou "key: 4989..." ou " key : 4989..."
            m = re.match(r'\s*key\s*:\s*([0-9a-fA-F]+)\s*$', line, re.IGNORECASE)
            if m:
                key = m.group(1).strip()
                continue
            m2 = re.match(r'\s*iv\s*:\s*([0-9a-fA-F]+)\s*$', line, re.IGNORECASE)
            if m2:
                iv = m2.group(1).strip()
                continue
    if not key or not iv:
        raise ValueError("Impossible de trouver 'key' et/ou 'iv' dans keyfile.txt (format attendu: key:HEX / iv:HEX)")
    return key, iv

def read_ciphertext_from_json(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{path} introuvable")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # chemin attendu: data["packet"]["record"]["ciphertext"]
    # on tente d'être tolérant si structure différente
    def find_cipher(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if k.lower() == "ciphertext" and isinstance(v, str):
                    return v
                res = find_cipher(v)
                if res:
                    return res
        elif isinstance(d, list):
            for item in d:
                res = find_cipher(item)
                if res:
                    return res
        return None
    ciph = find_cipher(data)
    if not ciph:
        raise ValueError("ciphertext introuvable dans le JSON")
    # nettoie espaces et guillemets éventuels
    return re.sub(r'\s+', '', ciph)

def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        raise ValueError("Données vides pour le dépadding")
    pad_len = b[-1]
    if pad_len < 1 or pad_len > 16:
        # probablement pas du PKCS#7 mais on renvoie brut
        return b
    if b[-pad_len:] != bytes([pad_len]) * pad_len:
        # padding invalide -> renvoie brut
        return b
    return b[:-pad_len]

def decrypt_with_pycrypto(key_hex, iv_hex, cipher_bytes):
    try:
        from Crypto.Cipher import AES  # pycryptodome
    except Exception as e:
        raise ImportError("pycryptodome non disponible") from e
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Longueur de clé invalide: {len(key)} octets")
    if len(iv) != 16:
        raise ValueError(f"Longueur IV invalide: {len(iv)} octets (doit être 16)")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(cipher_bytes)
    return pkcs7_unpad(plain)

def decrypt_with_openssl(key_hex, iv_hex, cipher_bytes):
    # appel à openssl enc -d -aes-128-cbc -K <key> -iv <iv>
    if not shutil.which("openssl"):
        raise FileNotFoundError("openssl introuvable dans le PATH")
    proc = subprocess.Popen(
        ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key_hex, "-iv", iv_hex],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate(input=cipher_bytes)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl a échoué: {err.decode(errors='replace')}")
    # openssl fera normalement le dépadding PKCS#7 lui-même
    return out

def main():
    try:
        key_hex, iv_hex = read_keyfile(KEYFILE)
    except Exception as e:
        print("Erreur en lisant la clé/IV:", e, file=sys.stderr)
        sys.exit(2)

    try:
        cipher_hex = read_ciphertext_from_json(JSON_FILE)
    except Exception as e:
        print("Erreur en lisant le JSON:", e, file=sys.stderr)
        sys.exit(3)

    try:
        cipher_bytes = unhexlify(cipher_hex)
    except Exception as e:
        print("Erreur: ciphertext n'est pas un hex valide:", e, file=sys.stderr)
        sys.exit(4)

    # Essaye pycryptodome d'abord (le plus portable en Python)
    plaintext = None
    try:
        plaintext = decrypt_with_pycrypto(key_hex, iv_hex, cipher_bytes)
        method = "pycryptodome"
    except ImportError:
        # tente openssl en fallback
        try:
            plaintext = decrypt_with_openssl(key_hex, iv_hex, cipher_bytes)
            method = "openssl"
        except Exception as e:
            print("Aucun moyen de déchiffrer : ni pycryptodome ni openssl disponibles/compatibles.", file=sys.stderr)
            print("Détails:", e, file=sys.stderr)
            print("\nSolution: installez pycryptodome :\n    pip3 install pycryptodome\nou assurez-vous que la commande 'openssl' est disponible.", file=sys.stderr)
            sys.exit(5)
    except Exception as e:
        # autre erreur avec pycryptodome
        print("Erreur lors du déchiffrement avec pycryptodome:", e, file=sys.stderr)
        # tente openssl en fallback
        try:
            plaintext = decrypt_with_openssl(key_hex, iv_hex, cipher_bytes)
            method = "openssl"
        except Exception as e2:
            print("Fallback openssl a aussi échoué:", e2, file=sys.stderr)
            sys.exit(6)

    # Affiche le résultat (essaye utf-8, sinon affichage 'replace')
    try:
        text = plaintext.decode("utf-8")
    except Exception:
        text = plaintext.decode("utf-8", errors="replace")

    print(f"Déchiffrement réussi (méthode: {method}).\nMessage déchiffré :\n")
    print("<TODO: nom de la variable contenant le text ainsi dechiffré>") # à compléter
    # fin

if __name__ == "__main__":
    main()

