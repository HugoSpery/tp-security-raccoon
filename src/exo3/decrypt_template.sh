
#!/usr/bin/env bash
set -euo pipefail
JSON_FILE="<TODO>" # à compléter
KEYFILE="<TODO>" # à compléter
CIPHERTEXT_BIN="ciphertext.bin"
DECRYPTED="decrypted.txt"

# Vérifie présence des fichiers
[ -f "$JSON_FILE" ] || { echo "Erreur: $JSON_FILE introuvable."; exit 1; }
[ -f "$KEYFILE" ] || { echo "Erreur: $KEYFILE introuvable."; exit 1; }

# Récupère clé et IV depuis keyfile.txt
KEY_HEX=$(grep '^key:' "<TODO>" | cut -d: -f2) # à compléter
IV_HEX=$(grep '^iv:' "<TODO>" | cut -d: -f2) # à compléter

# Récupère ciphertext depuis JSON
CIPHER_HEX=$(grep -oP '"ciphertext"\s*:\s*"\K[0-9a-fA-F]+' "<TODO>") # à compléter
if [ -z "$CIPHER_HEX" ]; then
  echo "Erreur : ciphertext vide dans $JSON_FILE"
  exit 1
fi

# Convertit hex -> binaire
printf "%s" "<TODO>" | awk '{for(i=1;i<=length;i+=2) printf "%c", strtonum("0x" substr($0,i,2))}' > "$CIPHERTEXT_BIN"  # à compléter

# Déchiffre
openssl enc -d -aes-128-cbc -K "<TODO>" -iv "<TODO>" -in "$CIPHERTEXT_BIN" -out "$DECRYPTED" # à compléter

# Affiche le message correctement
echo "Message déchiffré :"
cat "$DECRYPTED"
echo    # <- assure un retour à la ligne final

# Nettoyage
rm -f "$CIPHERTEXT_BIN" "$DECRYPTED"
