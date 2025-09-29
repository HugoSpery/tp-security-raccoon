#!/bin/bash

echo "=== Test de détection des clés DH statiques pour l'attaque Raccoon ==="
echo "Serveur cible: localhost:8443"
echo

# Fonction pour extraire les données ServerKeyExchange
extract_ske() {
    echo -n | openssl s_client -connect localhost:8443 -tls1_2 -msg 2>&1 | \
    grep -A 1 "ServerKeyExchange" | tail -1 | tr -d ' \n'
}

echo "Capture de 5 échanges ServerKeyExchange..."
echo

for i in {1..5}; do
    echo "Connexion $i:"
    ske_data=$(extract_ske)
    if [ -n "$ske_data" ]; then
        echo "  ServerKeyExchange data: ${ske_data:0:50}..."
        echo "$ske_data" > /tmp/ske_$i.txt
    else
        echo "  Aucune donnée ServerKeyExchange capturée"
    fi
    sleep 1
done

echo
echo "=== Analyse des résultats ==="

# Comparer les fichiers
if [ -f "/tmp/ske_1.txt" ] && [ -f "/tmp/ske_2.txt" ]; then
    if diff /tmp/ske_1.txt /tmp/ske_2.txt > /dev/null; then
        echo "✅ VULNÉRABLE: Les clés DH semblent STATIQUES (identiques entre connexions)"
        echo "   → L'attaque Raccoon pourrait être possible"
    else
        echo "❌ NON VULNÉRABLE: Les clés DH sont différentes (éphémères)"
        echo "   → L'attaque Raccoon n'est pas applicable"
    fi
else
    echo "⚠️  Impossible de capturer les données ServerKeyExchange"
    echo "   → Le serveur pourrait ne pas supporter DHE ou avoir un problème de configuration"
fi

echo
echo "=== Informations supplémentaires ==="
echo "Erreur observée: 'dh key too small'"
echo "Cela signifie que le serveur utilise des clés DH < 2048 bits"
echo "Pour l'attaque Raccoon, vous devrez peut-être:"
echo "1. Forcer l'utilisation de ciphers DH avec des clés plus petites"
echo "2. Ou reconfigurer le serveur pour accepter des clés DH plus petites"

# Nettoyer les fichiers temporaires
rm -f /tmp/ske_*.txt