#!/usr/bin/env bash
set -euo pipefail

JSON_FILE="capture.json"
KEYFILE="keyfile.txt"
CIPHERTEXT_BIN="ciphertext.bin"
DECRYPTED="decrypted.txt"

# Vérifie présence des fichiers
[ -f "$JSON_FILE" ] || { echo "Erreur: $JSON_FILE introuvable."; exit 1; }
[ -f "$KEYFILE" ] || { echo "Erreur: $KEYFILE introuvable."; exit 1; }

# Récupère clé et IV depuis keyfile.txt
KEY_HEX=$(grep '^key:' "$KEYFILE" | cut -d: -f2)
IV_HEX=$(grep '^iv:' "$KEYFILE" | cut -d: -f2)

# Récupère ciphertext depuis JSON
CIPHER_HEX=$(grep -oP '"ciphertext"\s*:\s*"\K[0-9a-fA-F]+' "$JSON_FILE")

if [ -z "$CIPHER_HEX" ]; then
  echo "Erreur : ciphertext vide dans $JSON_FILE"
  exit 1
fi

# Convertit hex -> binaire sans xxd
printf "%s" "$CIPHER_HEX" | awk '{for(i=1;i<=length;i+=2) printf "%c", strtonum("0x" substr($0,i,2))}' > "$CIPHERTEXT_BIN"

# Déchiffre
openssl enc -d -aes-128-cbc -K "$KEY_HEX" -iv "$IV_HEX" -in "$CIPHERTEXT_BIN" -out "$DECRYPTED"

# Affiche le message correctement
echo "Message déchiffré :"
cat "$DECRYPTED"
echo

# Nettoyage
rm -f "$CIPHERTEXT_BIN" "$DECRYPTED"
