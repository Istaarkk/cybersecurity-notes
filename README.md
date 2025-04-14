# Notes & Recherches Cybersécurité

Site statique Hugo pour organiser et partager des notes techniques, recherches et ressources en cybersécurité.

## 🚀 Fonctionnalités

- Thème sombre optimisé pour la lecture de code
- Shortcodes personnalisés pour les notes, avertissements et références d'outils
- Coloration syntaxique avec highlight.js
- Boutons de copie pour les blocs de code
- Navigation intuitive avec breadcrumbs
- Responsive design

## 📁 Structure

```
.
├── content/               # Contenu du site
│   ├── notes/            # Notes rapides et commandes
│   ├── recherches/       # Recherches approfondies
│   ├── veille/          # Résumés de veille
│   └── outils/          # Documentation d'outils
├── layouts/              # Templates Hugo
│   ├── _default/        # Layouts par défaut
│   ├── partials/        # Composants réutilisables
│   └── shortcodes/      # Shortcodes personnalisés
└── static/              # Assets statiques
    ├── css/             # Styles CSS
    ├── js/              # Scripts JavaScript
    └── images/          # Images
```

## 🛠️ Installation

1. Installer Hugo (version 0.80.0 ou supérieure)
2. Cloner ce dépôt
3. Lancer le serveur de développement :
   ```bash
   hugo server -D
   ```

## 📝 Création de contenu

### Notes rapides
```bash
hugo new notes/YYYY-MM-DD-titre-note.md
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