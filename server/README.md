# Documentation du serveur TLS vulnérable

## Description

Ce serveur Nginx est configuré pour être vulnérable à l'attaque Raccoon. Il présente les caractéristiques suivantes :

### Vulnérabilités implémentées

1. **Réutilisation de clés DH statiques** : Le serveur utilise les mêmes paramètres DH pour toutes les connexions
2. **TLS 1.2 uniquement** : Pas de support pour TLS 1.3 qui corrige cette vulnérabilité
3. **Cipher suites DHE** : Utilisation exclusive de cipher suites Diffie-Hellman éphémères
4. **Pas de Perfect Forward Secrecy** : La réutilisation des clés compromet la sécurité à long terme

### Configuration technique

- **Protocole** : TLS 1.2 uniquement
- **Cipher suites** : DHE-RSA-AES256-GCM-SHA384, DHE-RSA-AES128-GCM-SHA256, etc.
- **Paramètres DH** : 1024 bits (taille réduite pour accélérer les tests)
- **Session cache** : Désactivé pour forcer de nouveaux handshakes

## Construction et exécution

```bash
# Construction de l'image
docker build -t raccoon-vulnerable-server ./server

# Exécution du conteneur
docker run -d -p 8443:443 --name raccoon-server raccoon-vulnerable-server

# Test de connectivité
curl -k https://localhost:8443/status

# Vérification des cipher suites supportées
openssl s_client -connect localhost:8443 -cipher DHE-RSA-AES256-GCM-SHA384
```

## Tests de vulnérabilité

Pour tester la vulnérabilité Raccoon :

1. Établir plusieurs connexions TLS vers le serveur
2. Capturer le trafic réseau
3. Analyser la réutilisation des paramètres DH
4. Utiliser les outils du dossier `raccoon-code/` pour l'exploitation

## Avertissement

⚠️ **Ce serveur est intentionnellement vulnérable** ⚠️

Ne jamais utiliser cette configuration en production. Elle est uniquement destinée à des fins éducatives et de recherche en sécurité.

## Logs et monitoring

- Logs d'accès SSL : `/var/log/nginx/ssl_access.log`
- Logs d'erreur SSL : `/var/log/nginx/ssl_error.log`
- Configuration visible via l'endpoint `/status`