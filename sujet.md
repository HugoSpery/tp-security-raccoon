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
- **20 bits** : Très facile à casser (démonstration)
- **50 bits** : Relativement rapide 
- **100 bits** : Plus difficile mais faisable

Vous pourrez observer la **différence de temps et de complexité** entre chaque taille de clé.

#### ⚠️ Note importante sur la simulation

**À titre informatif :** ce script ne s'exécute pas sur un vrai serveur TLS et "triche" dans les calculs. En effet, une attaque réelle prendrait énormément de temps car :
- Les vrais serveurs utilisent des clés d'au minimum **1024 bits** (voire 2048+ bits)
- L'attaquant devrait mesurer lui-même les timings et construire la matrice de réduction
- Le processus de réduction de réseau serait beaucoup plus long

Cette simulation permet donc de comprendre les **principes théoriques** de l'attaque dans un temps raisonnable.

#### Exécution du script

**Prérequis :** Avoir SageMath installé sur votre machine.

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

⚠️ **Attention :** Cet exercice se fait dans un **vdn**. Il faut recloner le projet.

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

## Exercice 3 : Déchiffrer trame TLS
