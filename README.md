# 🔒 WriteUps & Recherches Cybersécurité

[![Hugo](https://img.shields.io/badge/Hugo-Extended-blueviolet.svg)](https://gohugo.io/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Deployed%20on-GitHub%20Pages-brightgreen.svg)](https://Istaarkk.github.io/cybersecurity-notes/)

Blog moderne de cybersécurité avec writeups CTF détaillés, analyses de vulnérabilités et outils de sécurité. Interface élégante et système de création d'articles simplifié.

## ✨ Fonctionnalités

### 🎨 Design Moderne
- **Interface élégante** avec design system cohérent
- **Responsive** adapté à tous les écrans
- **Animations fluides** et transitions soignées
- **Thème sombre/clair** pour le code
- **Typographie optimisée** (fonts Inter & JetBrains Mono)

### 🔍 Navigation Avancée
- **Recherche en temps réel** dans tous les articles
- **Filtrage par catégories** et tags
- **Tri intelligent** (date, titre, pertinence)
- **Navigation contextuelle** avec breadcrumbs
- **Articles similaires** automatiques

### 📝 Création Simplifiée
- **Scripts interactifs** pour créer des writeups
- **Templates pré-configurés** par type d'article
- **Validation automatique** des métadonnées
- **Makefile** avec commandes pratiques

### 🚀 Performance
- **Hugo optimisé** avec minification
- **CSS moderne** avec variables CSS
- **Images optimisées** automatiquement
- **SEO intégré** avec métadonnées

## 🛠️ Installation Rapide

### Prérequis
- [Hugo Extended](https://gohugo.io/installation/) (v0.100.0+)
- [Git](https://git-scm.com/)
- [Make](https://www.gnu.org/software/make/) (optionnel mais recommandé)

### Setup en une commande
```bash
git clone https://github.com/Istaarkk/cybersecurity-notes.git
cd cybersecurity-notes
make setup  # Installe Hugo + configure les scripts
```

### Ou manuellement
```bash
# Clone du repo
git clone https://github.com/Istaarkk/cybersecurity-notes.git
cd cybersecurity-notes

# Installation des dépendances (Ubuntu/Debian)
sudo apt update && sudo apt install hugo

# Ou avec Homebrew (macOS)
brew install hugo

# Rendre les scripts exécutables
chmod +x scripts/*.sh
```

## 🚀 Utilisation

### Commandes Principales

```bash
# Lancer le serveur de développement
make serve
# ou : hugo server -D

# Créer un nouveau writeup (interactif)
make new-writeup

# Créer un article de veille/outils
make new-article

# Compiler le site
make build

# Voir toutes les commandes
make help
```

### Création d'Articles

#### 📝 Nouveau WriteUp CTF
```bash
make new-writeup
```
Le script vous guidera pour :
- Titre du challenge
- Nom du CTF et date
- Catégorie (pwn, web, reverse, etc.)
- Tags spécialisés
- Difficulté et points
- Template pré-rempli avec structure standard

#### 📰 Article de Veille
```bash
make new-article
# Choisir "veille" → Template pour analyses de vulnérabilités
```

#### 🔧 Nouvel Outil
```bash
make new-article  
# Choisir "outils" → Template pour scripts et outils
```

### Structure des Fichiers

```
content/
├── writeups/           # WriteUps CTF
│   ├── breizh-ctf/
│   ├── fcsc/
│   └── ...
├── veille/            # Articles de veille sécurité
├── outils/            # Scripts et outils
└── _index.md          # Page d'accueil

layouts/
├── _default/
│   ├── baseof.html    # Layout de base
│   ├── single.html    # Articles individuels
│   ├── list.html      # Pages de liste
│   └── index.html     # Page d'accueil
└── partials/          # Composants réutilisables

static/
├── css/
│   └── modern-theme.css  # Styles principaux
├── images/
└── js/
```

## 📖 Guide d'Écriture

### Front Matter Standard

```yaml
---
title: "Mon WriteUp"
date: 2024-01-15
draft: false
tags: ["pwn", "buffer-overflow", "rop"]
categories: ["pwn"]
ctfs: ["FCSC"]
difficulty: "moyen"
points: 250
description: "Buffer overflow avec ROP chain"
---
```

### Structure Recommandée (WriteUp)

```markdown
# Challenge Name - CTF Name

## Challenge Description
Description du challenge fournie

## Reconnaissance Initiale
Première analyse, fichiers fournis

## Analyse
### Étape 1: Analyse statique
### Étape 2: Analyse dynamique

## Exploitation
Script final et explication

## Flag
```flag{example}```

## Conclusion
Résumé des techniques apprises
```

### Shortcodes Disponibles

```markdown
{{< alert type="info" >}}
Information importante
{{< /alert >}}

{{< alert type="warning" >}}
Attention à ce point
{{< /alert >}}

{{< alert type="danger" >}}
Élément critique
{{< /alert >}}
```

## 🎨 Personnalisation

### Couleurs et Thème
Modifiez les variables CSS dans `static/css/modern-theme.css` :

```css
:root {
  --primary-color: #2563eb;    /* Bleu principal */
  --secondary-color: #64748b;  /* Gris secondaire */
  --accent-color: #f59e0b;     /* Orange accent */
  /* ... */
}
```

### Configuration
Personnalisez `config.yaml` :

```yaml
params:
  author: "Votre Nom"
  description: "Votre description"
  social:
    github: "votre-username"
    twitter: "votre-handle"
```

## 📊 Statistiques

Visualisez vos stats :
```bash
make stats
```

Exemple de sortie :
```
📊 Statistiques du site
=======================
WriteUps: 42
Articles de veille: 15
Outils: 8
Total pages: 65
Images: 120
CSS personnalisés: 5
```

## 🚀 Déploiement

### GitHub Pages (Automatique)
Le site se déploie automatiquement via GitHub Actions sur chaque push.

### Déploiement Manuel
```bash
# Compilation pour production
make build

# Déploiement rapide (avec git)
make deploy-gh
```

### Autres Plateformes
- **Netlify**: Connectez votre repo, Hugo détecté automatiquement
- **Vercel**: Import depuis GitHub, configuration automatique
- **Firebase Hosting**: `firebase deploy` après `make build`

## 🔧 Maintenance

### Sauvegardes
```bash
make backup  # Crée backup-YYYYMMDD-HHMMSS.tar.gz
```

### Nettoyage
```bash
make clean   # Supprime les fichiers générés
```

### Vérifications
```bash
make check   # Vérifie la configuration Hugo
make lint    # Vérifie la syntaxe Markdown (si markdownlint installé)
```

## 🤝 Contribution

### Ajouter un WriteUp
1. Utilisez `make new-writeup`
2. Complétez le contenu
3. Testez avec `make serve`
4. Commitez et pushez

### Signaler un Bug
Ouvrez une [issue](https://github.com/Istaarkk/cybersecurity-notes/issues) avec :
- Description du problème
- Étapes pour reproduire
- Navigateur/OS utilisé

### Proposer une Amélioration
1. Forkez le projet
2. Créez une branche feature
3. Implémentez vos changements
4. Ouvrez une Pull Request

## 📚 Ressources

### Hugo
- [Documentation Hugo](https://gohugo.io/documentation/)
- [Themes Hugo](https://themes.gohugo.io/)
- [Hugo Forum](https://discourse.gohugo.io/)

### Cybersécurité
- [OWASP](https://owasp.org/)
- [CTF Time](https://ctftime.org/)
- [Exploit Database](https://www.exploit-db.com/)

### Markdown
- [Guide Markdown](https://www.markdownguide.org/)
- [Syntax Highlighting](https://highlightjs.org/)

## 📄 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- [Hugo](https://gohugo.io/) pour le générateur de site statique
- [Font Awesome](https://fontawesome.com/) pour les icônes
- [Highlight.js](https://highlightjs.org/) pour la coloration syntaxique
- [Inter](https://rsms.me/inter/) et [JetBrains Mono](https://www.jetbrains.com/mono/) pour les polices

---

<div align="center">
  
**🔒 Fait avec ❤️ pour la communauté cybersécurité**

[![GitHub stars](https://img.shields.io/github/stars/Istaarkk/cybersecurity-notes.svg?style=social&label=Star)](https://github.com/Istaarkk/cybersecurity-notes)
[![Follow](https://img.shields.io/github/followers/Istaarkk.svg?style=social&label=Follow)](https://github.com/Istaarkk)

</div> 