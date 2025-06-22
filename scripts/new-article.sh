#!/bin/bash

# Script pour créer un nouvel article (veille, outils, etc.)
# Usage: ./scripts/new-article.sh

set -e

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}📄 Créateur d'Articles - Cybersécurité${NC}"
echo -e "${BLUE}====================================\n${NC}"

# Fonction pour poser une question
ask() {
    local question=$1
    local var_name=$2
    local default=$3
    
    if [ -n "$default" ]; then
        echo -e "${CYAN}$question${NC} ${YELLOW}[$default]${NC}: "
    else
        echo -e "${CYAN}$question${NC}: "
    fi
    
    read -r input
    if [ -z "$input" ] && [ -n "$default" ]; then
        input=$default
    fi
    
    declare -g "$var_name=$input"
}

# Fonction de choix
choose() {
    local question=$1
    shift
    local options=("$@")
    
    echo -e "${CYAN}$question${NC}"
    for i in "${!options[@]}"; do
        echo -e "${YELLOW}$((i+1))${NC}. ${options[i]}"
    done
    
    while true; do
        echo -e "${CYAN}Choix (1-${#options[@]})${NC}: "
        read -r choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "${options[$((choice-1))]}"
            return
        else
            echo -e "${RED}Choix invalide.${NC}"
        fi
    done
}

# Questions principales
ask "Titre de l'article" "title"
ask "Date (YYYY-MM-DD)" "date" "$(date +%Y-%m-%d)"

# Type d'article
type=$(choose "Type d'article :" "veille" "outils" "general")

# Description
ask "Description courte" "description"

# Tags selon le type
if [ "$type" = "veille" ]; then
    echo -e "\n${GREEN}Tags suggérés pour la veille :${NC}"
    echo "vulnerability, cve, security-news, malware, apt, breach, patch, 0day"
    ask "Tags (séparés par des virgules)" "tags" "vulnerability, security-news"
elif [ "$type" = "outils" ]; then
    echo -e "\n${GREEN}Tags suggérés pour les outils :${NC}"
    echo "python, bash, powershell, automation, pentesting, forensics, analysis"
    ask "Tags (séparés par des virgules)" "tags" "python, automation"
else
    ask "Tags (séparés par des virgules)" "tags" "cybersecurity"
fi

# Création du nom de fichier
filename_date=$(date -d "$date" +%Y-%m-%d)
filename_title=$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
filename="${filename_date}-${filename_title}.md"

# Répertoire de destination
dir="content/$type"
mkdir -p "$dir"
filepath="$dir/$filename"

# Vérification
if [ -f "$filepath" ]; then
    ask "Le fichier existe déjà. Écraser ? (y/N)" "overwrite" "N"
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Annulé.${NC}"
        exit 1
    fi
fi

# Conversion des tags
IFS=',' read -ra tag_array <<< "$tags"
formatted_tags=""
for tag in "${tag_array[@]}"; do
    tag=$(echo "$tag" | xargs) # trim whitespace
    formatted_tags="$formatted_tags\"$tag\", "
done
formatted_tags=$(echo "$formatted_tags" | sed 's/, $//')

# Contenu selon le type
if [ "$type" = "veille" ]; then
    cat > "$filepath" << EOF
---
title: "$title"
date: $date
draft: false
tags: [$formatted_tags]
categories: ["veille"]
description: "$description"
---

# $title

## Résumé

<!-- Résumé de l'information -->

## Détails

<!-- Détails de la vulnérabilité/actualité -->

### Impact

<!-- Quel est l'impact ? -->

### Mitigation

<!-- Comment se protéger ? -->

## Sources

- [Source 1](https://example.com)
- [CVE](https://cve.mitre.org/)

## Timeline

- **Date de découverte:** 
- **Date de publication:** 
- **Patch disponible:** 

---

**Criticité:** Faible/Moyenne/Élevée/Critique  
**Secteurs affectés:** 
EOF

elif [ "$type" = "outils" ]; then
    cat > "$filepath" << EOF
---
title: "$title"
date: $date
draft: false
tags: [$formatted_tags]
categories: ["outils"]
description: "$description"
---

# $title

## Description

<!-- Description de l'outil -->

## Installation

\`\`\`bash
# Commandes d'installation
\`\`\`

## Usage

\`\`\`bash
# Exemples d'utilisation
\`\`\`

## Code Source

\`\`\`python
#!/usr/bin/env python3
# Votre code ici
\`\`\`

## Fonctionnalités

- [ ] Fonctionnalité 1
- [ ] Fonctionnalité 2
- [ ] Fonctionnalité 3

## Prérequis

- Python 3.x
- Autres dépendances

## Exemples

### Exemple 1

\`\`\`bash
./script.py --option value
\`\`\`

## Licence

MIT/GPL/Autre

---

**Langage:** Python/Bash/Autre  
**Plateforme:** Linux/Windows/MacOS  
**Version:** 1.0
EOF

else
    cat > "$filepath" << EOF
---
title: "$title"
date: $date
draft: false
tags: [$formatted_tags]
categories: ["general"]
description: "$description"
---

# $title

## Introduction

<!-- Introduction du sujet -->

## Contenu Principal

<!-- Votre contenu ici -->

## Conclusion

<!-- Conclusion -->

---

**Catégorie:** Général
EOF
fi

echo -e "\n${GREEN}✅ Article créé !${NC}"
echo -e "${BLUE}📁 Emplacement:${NC} $filepath"

# Ouvrir le fichier
ask "Ouvrir maintenant ? (Y/n)" "open" "Y"
if [[ "$open" =~ ^[Yy]$ ]]; then
    if command -v code &> /dev/null; then
        code "$filepath"
    elif command -v nano &> /dev/null; then
        nano "$filepath"
    else
        echo -e "${YELLOW}Ouvrez: $filepath${NC}"
    fi
fi 