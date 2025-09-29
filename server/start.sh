#!/bin/bash

# Script de démarrage pour le serveur vulnérable Raccoon

echo "=== Démarrage du serveur TLS 1.2 vulnérable ==="
echo "Configuration: Réutilisation de clés DH statiques"
echo "Port: 443 (HTTPS)"
echo "Protocols: TLS 1.2 uniquement"
echo "Cipher suites: DHE-* (vulnérables à Raccoon)"

# Vérification des fichiers de configuration
echo "Vérification des certificats SSL..."
ls -la /etc/nginx/ssl/

echo "Vérification de la configuration Nginx..."
nginx -t

if [ $? -eq 0 ]; then
    echo "Configuration Nginx valide"
    
    # Affichage des informations sur les paramètres DH
    echo "=== Paramètres DH utilisés ==="
    openssl dhparam -in /etc/nginx/ssl/dhparam.pem -text -noout | head -20
    
    echo "=== Démarrage de Nginx ==="
    nginx -g 'daemon off;'
else
    echo "Erreur dans la configuration Nginx"
    exit 1
fi