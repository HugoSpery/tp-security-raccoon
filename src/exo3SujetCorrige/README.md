# Exercice 3 (version 2) : Déchiffrement d'un ApplicationData TLS 1.2 (script à trous)

⚠️ **Attention :** Cet exercice se fait **en dehors de vdn**.

## But de l'exercice
Tu disposes :
- d'une **clé AES** et d'un **IV** (extrait·e·s via une attaque — ex. RACOON) stockés dans un fichier,
- d'une **trace JSON** (`capture.json`) simulant un enregistrement TLS 1.2 contenant un champ `ciphertext` (hex) représentant un `ApplicationData` chiffré.

Objectif : compléter le script `decrypt_template.py` (version *à trous* fournie ci-dessous) en remplaçant les `# TODO` indiqués pour que le script lise la clé/IV, récupère le ciphertext depuis le JSON, le déchiffre (via pycryptodome si disponible, sinon `openssl`) et affiche le message clair.

---

## Fichier cible
`decrypt_template.py` — script Python à trous. Le fichier fourni contient exactement ces `# TODO` :

```
# --- Variables à compléter ---
JSON_FILE = "<TODO: nom du fichier JSON>" # à compléter
KEYFILE = "<TODO: nom du fichier contenant la clé>" # à compléter
...
print("<TODO: nom de la variable contenant le plain text ainsi dechiffré>") # à compléter
```
