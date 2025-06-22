#!/bin/bash

# Script pour créer un nouveau writeup facilement
# Usage: ./scripts/new-writeup.sh

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 Créateur de WriteUp - Cybersécurité${NC}"
echo -e "${BLUE}=====================================\n${NC}"

# Fonction pour afficher une question
ask_question() {
    local question=$1
    local var_name=$2
    local default_value=$3
    
    if [ -n "$default_value" ]; then
        echo -e "${CYAN}$question${NC} ${YELLOW}[$default_value]${NC}: "
    else
        echo -e "${CYAN}$question${NC}: "
    fi
    
    read -r input
    if [ -z "$input" ] && [ -n "$default_value" ]; then
        input=$default_value
    fi
    
    declare -g "$var_name=$input"
}

# Fonction pour choisir dans une liste
choose_from_list() {
    local question=$1
    shift
    local options=("$@")
    
    echo -e "${CYAN}$question${NC}"
    for i in "${!options[@]}"; do
        echo -e "${YELLOW}$((i+1))${NC}. ${options[i]}"
    done
    
    while true; do
        echo -e "${CYAN}Votre choix (1-${#options[@]})${NC}: "
        read -r choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "${options[$((choice-1))]}"
            return
        else
            echo -e "${RED}Choix invalide. Veuillez choisir un nombre entre 1 et ${#options[@]}.${NC}"
        fi
    done
}

# Fonction pour choisir plusieurs options
choose_multiple() {
    local question=$1
    shift
    local options=("$@")
    
    echo -e "${CYAN}$question${NC}"
    echo -e "${YELLOW}Séparez vos choix par des espaces (ex: 1 3 5)${NC}"
    
    for i in "${!options[@]}"; do
        echo -e "${YELLOW}$((i+1))${NC}. ${options[i]}"
    done
    
    echo -e "${CYAN}Vos choix${NC}: "
    read -r choices
    
    local selected=()
    for choice in $choices; do
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            selected+=("${options[$((choice-1))]}")
        fi
    done
    
    echo "${selected[*]}"
}

# Questions pour créer le writeup
echo -e "${GREEN}📝 Informations du WriteUp${NC}\n"

ask_question "Titre du challenge" "title"
ask_question "Nom du CTF" "ctf_name"
ask_question "Date du CTF (YYYY-MM-DD)" "ctf_date" "$(date +%Y-%m-%d)"

# Choix de la catégorie principale
category=$(choose_from_list "Catégorie principale :" "pwn" "web" "reverse" "network" "crypto" "forensics" "misc")

# Choix des tags
echo -e "\n${GREEN}🏷️  Tags du WriteUp${NC}\n"
available_tags=("buffer-overflow" "rop" "format-string" "shellcode" "heap" "stack" "xss" "sqli" "csrf" "lfi" "rfi" "upload" "serialization" "ghidra" "ida" "radare2" "gdb" "pwntools" "wireshark" "nmap" "metasploit" "burp" "john" "hashcat" "steganography" "cryptanalysis" "rsa" "aes")

tags_input=$(choose_multiple "Sélectionnez les tags pertinents :" "${available_tags[@]}")
IFS=' ' read -ra selected_tags <<< "$tags_input"

# Choix de la difficulté
difficulty=$(choose_from_list "Difficulté du challenge :" "facile" "moyen" "difficile" "expert")

# Description courte
ask_question "Description courte du challenge" "description"

# Points/Score
ask_question "Points obtenus" "points" "0"

# Création du nom de fichier
filename_date=$(date -d "$ctf_date" +%Y-%m-%d)
filename_title=$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
filename="${filename_date}-${ctf_name,,}-${filename_title}.md"

# Choix du répertoire de destination
ctf_dir="content/writeups/${ctf_name,,}"
if [ ! -d "$ctf_dir" ]; then
    echo -e "${YELLOW}Le répertoire $ctf_dir n'existe pas. Création...${NC}"
    mkdir -p "$ctf_dir"
fi

filepath="$ctf_dir/$filename"

# Vérification si le fichier existe déjà
if [ -f "$filepath" ]; then
    echo -e "${RED}⚠️  Le fichier $filepath existe déjà !${NC}"
    ask_question "Voulez-vous l'écraser ? (y/N)" "overwrite" "N"
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Opération annulée.${NC}"
        exit 1
    fi
fi

# Génération du contenu du fichier
cat > "$filepath" << EOF
---
title: "$title"
date: $ctf_date
draft: false
tags: [$(printf '"%s", ' "${selected_tags[@]}" | sed 's/, $//')$([ ${#selected_tags[@]} -eq 0 ] && echo '' || echo ', ')"$category"]
categories: ["$category"]
ctfs: ["$ctf_name"]
difficulty: "$difficulty"
points: $points
description: "$description"
---

# $title - $ctf_name

## Challenge Description

<!-- Décrivez ici le challenge et ce qui était demandé -->

## Reconnaissance Initiale

<!-- Première analyse du challenge, fichiers fournis, etc. -->

## Analyse

<!-- Analyse détaillée du problème -->

### Étape 1: [Titre de l'étape]

<!-- Description de la première étape -->

\`\`\`bash
# Commandes utilisées
\`\`\`

### Étape 2: [Titre de l'étape]

<!-- Description de la deuxième étape -->

\`\`\`python
# Script Python si applicable
\`\`\`

## Exploitation

<!-- Description de l'exploitation -->

### Script Final

\`\`\`python
#!/usr/bin/env python3
from pwn import *

# Configuration
HOST = "hostname"
PORT = 1337

# Connection
if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = process("./binary")

# Exploitation
# Votre code ici

io.interactive()
\`\`\`

## Flag

\`\`\`
flag{example_flag_here}
\`\`\`

## Conclusion

<!-- Résumé de ce qui a été appris, techniques utilisées -->

## Ressources

- [Lien utile 1](http://example.com)
- [Lien utile 2](http://example.com)

---

**Points obtenus:** $points  
**Difficulté:** $difficulty  
**CTF:** $ctf_name
EOF

echo -e "\n${GREEN}✅ WriteUp créé avec succès !${NC}"
echo -e "${BLUE}📁 Emplacement:${NC} $filepath"
echo -e "${PURPLE}📝 Vous pouvez maintenant éditer le fichier et ajouter votre contenu.${NC}"

# Proposer d'ouvrir le fichier
ask_question "Voulez-vous ouvrir le fichier maintenant ? (Y/n)" "open_file" "Y"
if [[ "$open_file" =~ ^[Yy]$ ]]; then
    if command -v code &> /dev/null; then
        echo -e "${BLUE}🚀 Ouverture avec VS Code...${NC}"
        code "$filepath"
    elif command -v nano &> /dev/null; then
        echo -e "${BLUE}🚀 Ouverture avec nano...${NC}"
        nano "$filepath"
    elif command -v vim &> /dev/null; then
        echo -e "${BLUE}🚀 Ouverture avec vim...${NC}"
        vim "$filepath"
    else
        echo -e "${YELLOW}⚠️  Aucun éditeur détecté. Ouvrez manuellement: $filepath${NC}"
    fi
fi

echo -e "\n${GREEN}🔒 WriteUp prêt ! N'oubliez pas de :${NC}"
echo -e "${YELLOW}  1. Compléter le contenu${NC}"
echo -e "${YELLOW}  2. Ajouter les captures d'écran si nécessaire${NC}"
echo -e "${YELLOW}  3. Tester la compilation avec 'hugo server -D'${NC}"
echo -e "${YELLOW}  4. Retirer 'draft: false' quand terminé${NC}" 