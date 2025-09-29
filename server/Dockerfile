# Dockerfile pour serveur web vulnérable TLS 1.2 avec réutilisation de clés DH
# Ce serveur est configuré pour démontrer la vulnérabilité Raccoon Attack
# Utilisation d'Ubuntu 18.04 avec des versions plus anciennes d'OpenSSL/Nginx

FROM ubuntu:18.04

# Éviter les prompts interactifs
ENV DEBIAN_FRONTEND=noninteractive

# Installation des dépendances avec des versions plus anciennes
RUN apt-get update && apt-get install -y \
    nginx \
    openssl \
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Afficher les versions pour vérification
RUN echo "=== VERSIONS INSTALLÉES ===" && \
    openssl version && \
    nginx -v

# Création du répertoire pour les certificats et clés
RUN mkdir -p /etc/nginx/ssl

# Configuration OpenSSL très permissive pour les tests de vulnérabilité
RUN echo "# Configuration OpenSSL permissive pour tests Raccoon" > /etc/ssl/openssl_raccoon.cnf && \
    echo "MinProtocol = TLSv1" >> /etc/ssl/openssl_raccoon.cnf && \
    echo "MaxProtocol = TLSv1.2" >> /etc/ssl/openssl_raccoon.cnf && \
    echo "CipherString = DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ALL:@SECLEVEL=0" >> /etc/ssl/openssl_raccoon.cnf && \
    echo "Options = UnsafeLegacyRenegotiation" >> /etc/ssl/openssl_raccoon.cnf

# Génération d'une clé privée et certificat auto-signé avec paramètres compatibles
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj "/C=FR/ST=IDF/L=Paris/O=TestOrg/OU=TestUnit/CN=raccoon-server"

# Génération des paramètres DH très faibles (vulnérabilité intentionnelle)
# 1024 bits pour être compatible avec TLS 1.0/1.1
RUN openssl dhparam -out /etc/nginx/ssl/dhparam.pem 1024

# Ajuster les permissions SSL pour Ubuntu 18.04
RUN chmod 644 /etc/nginx/ssl/server.crt && \
    chmod 600 /etc/nginx/ssl/server.key && \
    chmod 644 /etc/nginx/ssl/dhparam.pem

# Configuration Nginx vulnérable
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/sites-available/default

# Page web simple pour les tests
COPY index.html /var/www/html/index.html

# Exposition du port HTTPS
EXPOSE 443

# Script de démarrage
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]