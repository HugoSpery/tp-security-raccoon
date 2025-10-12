# TP Sécurité : Attaque Raccoon

## Introduction

Ce TP vous permettra de découvrir et d'expérimenter l'**attaque Raccoon**, une vulnérabilité cryptographique qui exploite la réutilisation de clés dans les échanges Diffie-Hellman (DHE) en TLS.

L'attaque Raccoon tire parti du fait que certains serveurs TLS réutilisent la même clé privée Diffie-Hellman pour plusieurs connexions, permettant à un attaquant d'extraire cette clé secrète en observant suffisamment d'échanges.

**📚 Pour plus d'informations détaillées sur cette attaque, consultez : [raccoon-attack.com](https://raccoon-attack.com)**

## Objectifs du TP

- Comprendre les mécanismes de l'attaque Raccoon
- Expérimenter avec des implémentations vulnérables
- Utiliser des outils de réduction de réseau (lattice) pour retrouver des clés secrètes
- Analyser la vulnérabilité de serveurs TLS

---

## Exercice 1 : Test du script Raccoon

### Installation et préparation

1. **Cloner le dépôt du TP :**
   ```bash
   git clone https://github.com/HugoSpery/tp-security-raccoon.git
   ```

2. **Se positionner dans le dossier de l'exercice 1 :**
   ```bash
   cd tp-security-raccoon/src/exo1
   ```

3. **Vérifier le contenu du dossier :**
   ```bash
   ls -la
   ```

### Description de l'exercice

Le script `raccoon.sage` contient l'implémentation de l'attaque Raccoon permettant de récupérer la clé secrète Diffie-Hellman. Cependant, **le script contient des trous que vous devrez compléter** pour qu'il fonctionne correctement.

#### Paramètres testés

Le script teste l'attaque sur différentes tailles de clés :
- **20 bits** 
- **50 bits** 
- **100 bits**

Vous pourrez observer la **différence de temps et de complexité** entre chaque taille de clé.

#### ⚠️ Note importante sur la simulation

**À titre informatif :** ce script ne s'exécute pas sur un vrai serveur TLS et "triche" dans les calculs. En effet, une attaque réelle prendrait énormément de temps car :
- Les vrais serveurs utilisent des clés d'au minimum **1024 bits** (voire 2048+ bits)
- L'attaquant devrait mesurer lui-même les timings et construire la matrice de réduction
- Le processus de réduction de réseau serait beaucoup plus long

Cette simulation permet donc de comprendre les **principes théoriques** de l'attaque dans un temps raisonnable.

#### Exécution du script

**Prérequis :** Avoir SageMath installé sur votre machine.

**Avant de lancer le script, créez le dossier de sortie :**
```bash
mkdir output/
```

**Lancement :**
```bash
sage raccoon.sage
```

#### Résultats

Une fois le script terminé, les **résultats de l'attaque** se trouvent dans le dossier `output/` où vous pourrez voir les **clés déchiffrées** pour chaque test effectué.

```bash
cd output/
```

**📋 Questions à analyser :**

1. Que peut-on en déduire sur la sécurité selon la taille des clés ? 

#### 🎯 Bonus (optionnel)

Pour aller plus loin, vous pouvez tester l'attaque avec des clés plus grandes :

1. **Ajouter une nouvelle configuration** dans le fichier `common.json` avec une taille de clé plus importante (ex: 256 bits, 512 bits)
2. **Instancier cette nouvelle configuration** dans `raccoon.sage` en suivant l'exemple des lignes 197 à 206
3. **Observer les durées** nécessaires pour résoudre ces clés plus longues


## Exercice 2 : Serveur web vulnérable

### Installation et préparation

⚠️ **Attention :** Cet exercice se fait dans **vdn**. Il faut recloner le projet.

1. **Cloner à nouveau le dépôt du TP :**
   ```bash
   git clone https://github.com/HugoSpery/tp-security-raccoon.git
   ```

2. **Se positionner dans le dossier de l'exercice 2 :**
   ```bash
   cd tp-security-raccoon/src/exo2
   ```

### Description de l'exercice

Dans cet exercice, vous disposez d'un **serveur web malconfiguré** et sensible à l'attaque Raccoon. Votre mission est de **modifier la configuration** pour le protéger contre cette attaque.

**📚 Pour comprendre les configurations sécurisées, consultez : [raccoon-attack.com](https://raccoon-attack.com)**

#### Configuration du serveur

La configuration du serveur se trouve dans le fichier `docker-compose.yml`. C'est dans ce fichier que vous devrez apporter les modifications nécessaires. 

#### Commandes utiles

**Lancer ou relancer le serveur après modification :**
```bash
docker-compose up -d --force-recreate dh-reuse-server
```

**Tester la vulnérabilité du serveur :**
```bash
docker-compose run --rm raccoon-checker bash -lc "cd /work && python3 check_raccoon_vulnerability.py dh-reuse-server 443"
```

**📋 Questions à analyser :**

1. Quelles sont les différents problèmes de configuration sur ce serveur ? 
2. Quelles est la meilleur configuration possible pour être protégé au maximum de raccoon ?

## Exercice 3 : Déchiffrement d'un ApplicationData TLS 1.2 après attaque RACOON

⚠️ **Attention :** Si le script est non fonctionnel, une autre version de cet exercice est disponible dans **src/exo3SujetCorrige** (BONUS)
⚠️ **Attention :** Cet exercice se fait **en dehors de vdn**.

### Objectif

Tu disposes :
 - d'une **clé** obtenue via une attaque (ex: racoon) stockée dans un fichier séparé,
 - d'une **trace JSON** (`capture.json`) simulant un enregistrement TLS 1.2 contenant un
   champ `ciphertext` (hex) représentant un ApplicationData chiffré.

Le but de l'exercice :
 - compléter le script `decrypt_template.sh` en indiquant **où** chercher la clé/IV
   et **où** récupérer le ciphertext dans le JSON et comment les utiliser ; puis exécuter le script pour
   afficher le message clair (ici : `"message prive"`).

### Fichiers fournis

 - `capture.json` : JSON simulant un échange TLS1.2 entre deux IP.
   Structure minimale attendue :
   {
     "packet": {
       "src_ip": "192.168.1.2",
       "dst_ip": "192.168.1.10",
       ...
       "record": {
         "type": "ApplicationData",
         "cipher": "AES_128_CBC",
         "ciphertext": "<hex>"
       }
     }
   }

 - `keyfile.txt` : contient la clé et l'IV extraites par l'attaque (format simple attendu, exemple) :
   key:<hex>
   iv:<hex>

 - `decrypt_template.sh` : script à trous (2 emplacements "# à compléter") que tu dois éditer pour extraire :
   1) JSON_FILE="<TODO>" # à compléter
   2) KEYFILE="<TODO>" # à compléter
   3) KEY_HEX=$(grep '^key:' "<TODO>" | cut -d: -f2) # à compléter
   4) IV_HEX=$(grep '^iv:' "<TODO>" | cut -d: -f2) # à compléter
   5) CIPHER_HEX=$(grep -oP '"ciphertext"\s*:\s*"\K[0-9a-fA-F]+' "<TODO>") # à compléter
   6) printf "%s" "<TODO>" | awk '{for(i=1;i<=length;i+=2) printf "%c", strtonum("0x" substr($0,i,2))}' > "$CIPHERTEXT_BIN"  # à compléter
   7) openssl enc -d -aes-128-cbc -K "<TODO>" -iv "<TODO>" -in "$CIPHERTEXT_BIN" -out "$DECRYPTED" # à compléter


### Exécution

1. Rendre le script exécutable :
   chmod +x decrypt_template.sh

2. Éditer `decrypt_template.sh`

3. Lancer :
   ./decrypt_template.sh

### Résultat attendu

Le script doit afficher :
   Message déchiffré : <à trouver>

### Remarques

 - Cet exercice est une **simulation pédagogique** de l'étape de récupération/usage d'une clé compromise.

# Exercice 3 (version 2 - **BONUS**) : Déchiffrement d'un ApplicationData TLS 1.2 (script à trous)

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
