---
title: "PwnMe Junior 2025 - Evil-Hackers WriteUp"
date: 2024-04-14
description: "WriteUp du challenge Evil-Hackers du CTF PwnMe Junior 2025"
tags: ["pwn", "use-after-free", "ctf", "pwnme"]
categories: ["pwn"]
---

# PwnMe Junior 2025 - Evil-Hackers WriteUp

## Description du challenge
Le challenge Evil-Hackers est une épreuve de Use-After-Free (UAF) sur un binaire 64 bits. Le programme gère des connexions de hackers et contient une vulnérabilité dans sa gestion de la mémoire.

## Analyse du binaire

### Vérification des protections
```bash
$ checksec evil-hackers
[*] '/home/synapse/pwnme-junior-2025/pwn/Evil-Hackers/evil-hackers'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Vulnérabilité

### Analyse de la vulnérabilité
Le programme contient une vulnérabilité Use-After-Free dans son système de gestion de mémoire :
1. Le programme utilise un pointeur global (`global_hacker`) qui peut être libéré mais reste accessible
2. Le buffer de log initial fait 64 bytes
3. La réallocation mémoire se produit quand : `log_size + msg_len + 2 > log_capacity`
4. Chaque message de log ajoute :
   - La longueur du message
   - 2 bytes supplémentaires (1 pour le newline, 1 pour le null terminator)

## Exploitation

### Étapes d'exploitation
1. Appuyer sur `1` - Créer un hacker normal
2. Appuyer sur `4` - Ajouter un message de log avec exactement 63 'A's
3. Appuyer sur `3` - Déconnecter le hacker (déclenche la condition UAF)
4. Appuyer sur `5` - Créer un hacker d'élite (réutilise la mémoire libérée)
5. Appuyer sur `2` - Accéder aux données secrètes pour obtenir le flag

### Payload
Utiliser exactement 63 'A's comme message de log :
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

### Détails techniques
- Le buffer initial contient 19 bytes de "Normal connection."
- L'ajout de 63 'A's + 2 bytes = 65 bytes supplémentaires
- Le total devient 84 bytes, déclenchant une réallocation à 128 bytes
- Cela satisfait la condition nécessaire pour la création du hacker d'élite

## Flag
```
PWNME{JUNIOR_UAF_MASTER}
```

## Conclusion
Ce challenge était une excellente introduction aux vulnérabilités Use-After-Free. Les points clés étaient :
- Compréhension de la gestion de la mémoire du programme
- Calcul précis de la taille du message pour déclencher la réallocation
- Séquence correcte d'actions pour exploiter la vulnérabilité UAF 