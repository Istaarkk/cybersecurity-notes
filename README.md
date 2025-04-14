# WriteUps & Recherches Cybersécurité

Site statique Hugo pour organiser et partager des writeups techniques, recherches et ressources en cybersécurité.

## 🚀 Fonctionnalités

- Thème sombre optimisé pour la lecture de code
- Shortcodes personnalisés pour les writeups, avertissements et références d'outils
- Coloration syntaxique avec highlight.js
- Boutons de copie pour les blocs de code
- Navigation intuitive avec breadcrumbs
- Responsive design

## 📁 Structure

```
.
├── archetypes/        # Templates pour les nouveaux contenus
├── assets/           # Fichiers statiques (CSS, JS, images)
├── content/          # Contenu du site
│   ├── writeups/     # Writeups détaillés et commandes
│   ├── recherches/   # Analyses approfondies
│   ├── veille/       # Veille technologique
│   └── outils/       # Scripts et outils
├── layouts/          # Templates Hugo personnalisés
└── static/           # Fichiers statiques
```

## 🛠️ Installation

1. Installer Hugo (version 0.80.0 ou supérieure)
2. Cloner ce dépôt
3. Lancer le serveur de développement :
   ```bash
   hugo server -D
   ```

## 📝 Création de contenu

### Writeups rapides
```bash
hugo new writeups/YYYY-MM-DD-titre-writeup.md
```

### Recherches
```bash
hugo new recherches/YYYY-MM-DD-titre-recherche.md
```

### Veille
```bash
hugo new veille/YYYY-MM-DD-titre-veille.md
```

## 🔧 Shortcodes disponibles

### Note d'information
```markdown
{{< note >}}
Votre note ici
{{< /note >}}
```

### Avertissement
```markdown
{{< warning >}}
Votre avertissement ici
{{< /warning >}}
```

### Référence d'outil
```markdown
{{< tool name="nom-outil" link="https://..." >}}
Description de l'outil
{{< /tool >}}
```

## 📦 Déploiement

Le site est configuré pour être déployé sur GitHub Pages. Pour déployer :

1. Construire le site :
   ```bash
   hugo --minify
   ```

2. Le contenu sera dans le dossier `public/`

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails. 