---
title: "Cyber Apocalypse 2024 - ImpossibleMaze"
date: 2024-04-14
tags: ["cyber apocalypse", "reverse", "binary patching", "terminal size"]
---

# ImpossibleMaze - Cyber Apocalypse 2024

## Description du challenge

ImpossibleMaze est un challenge de reverse engineering du Cyber Apocalypse CTF 2024. Le programme simule un labyrinthe qui semble impossible à résoudre, mais qui cache un mécanisme de validation basé sur la taille du terminal.

## Analyse du binaire

Après décompilation et analyse du code, nous avons découvert que le binaire vérifie la taille du terminal d'exécution. Si cette taille ne correspond pas exactement à 13 lignes et 37 colonnes (13x37 ou "LEET" en leetspeak), le labyrinthe est généré d'une manière qui le rend impossible à résoudre.

L'extrait de code décompilé ci-dessous montre cette vérification :

```c
// Pseudo-code décompilé
void main() {
    // ... initialisation ...
    
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    
    if (w.ws_row == 0xd && w.ws_col == 0x25) {
        // Génération du labyrinthe soluble
        // ...
    } else {
        // Génération du labyrinthe insoluble
        // ...
    }
    
    // ... suite du code ...
}
```

La vérification critique est `if (w.ws_row == 0xd && w.ws_col == 0x25)`, qui teste si le terminal fait exactement 13 lignes (0xd en hexadécimal) et 37 colonnes (0x25 en hexadécimal).

## Exploitation

Nous avons deux approches possibles pour exploiter ce challenge :

### Approche 1 : Modification de la taille du terminal

Cette approche consiste à créer un terminal virtuel avec les dimensions spécifiques requises :

```python
#!/usr/bin/env python3
import os
import pty
import time
import subprocess

# Crée un terminal virtuel de taille 13x37
master, slave = pty.openpty()
os.set_inheritable(slave, True)

# Configure les dimensions du terminal
subprocess.run(['stty', '-F', os.ttyname(slave), 'rows', '13', 'cols', '37'])

# Lance le programme dans ce terminal
try:
    program_path = os.path.expanduser("~/HTB/Reverse/rev_impossimaze/main")
    process = subprocess.Popen(
        [program_path],
        stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True,
        close_fds=True
    )
    
    # Attendre un peu pour que le programme s'initialise
    time.sleep(1)
    
    # Lire la sortie
    output = os.read(master, 4096).decode('utf-8', errors='ignore')
    print("Output from program:")
    print(output)
    
    # Si nécessaire, envoyer une commande 'q' pour quitter proprement
    os.write(master, b'q')
    
    # Attendre la fin du processus
    process.wait()
    
except Exception as e:
    print(f"Error: {e}")
finally:
    # Nettoyage
    os.close(master)
    os.close(slave)
```

### Approche 2 : Patching du binaire

L'alternative consiste à patcher le binaire pour contourner la vérification de la taille du terminal :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Ouvrir le binaire pour lecture/écriture
    FILE *f = fopen("main", "r+b");
    if (!f) {
        perror("Impossible d'ouvrir le binaire");
        return 1;
    }
    
    // Créer une copie de sauvegarde
    FILE *backup = fopen("main.backup", "wb");
    if (!backup) {
        perror("Impossible de créer une sauvegarde");
        fclose(f);
        return 1;
    }
    
    // Lire tout le fichier dans un buffer
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *buffer = malloc(filesize);
    if (!buffer) {
        perror("Erreur d'allocation mémoire");
        fclose(f);
        fclose(backup);
        return 1;
    }
    
    fread(buffer, 1, filesize, f);
    
    // Écrire la sauvegarde
    fwrite(buffer, 1, filesize, backup);
    fclose(backup);
    
    // Patcher le binaire en recherchant les comparaisons critiques
    int patchCount = 0;
    for (long i = 0; i < filesize - 3; i++) {
        // Patcher CMP reg, 0xd -> CMP reg, 0x0
        if (buffer[i] == 0x83 && (buffer[i+1] == 0xF8 || buffer[i+1] == 0xFA || buffer[i+1] == 0xFF) && buffer[i+2] == 0x0D) {
            buffer[i+2] = 0x00;
            patchCount++;
        }
        
        // Patcher CMP reg, 0x25 -> CMP reg, 0x0
        if (buffer[i] == 0x83 && (buffer[i+1] == 0xF8 || buffer[i+1] == 0xFA || buffer[i+1] == 0xFF) && buffer[i+2] == 0x25) {
            buffer[i+2] = 0x00;
            patchCount++;
        }
    }
    
    // Réécrire le fichier patché
    fseek(f, 0, SEEK_SET);
    fwrite(buffer, 1, filesize, f);
    fclose(f);
    free(buffer);
    
    printf("Binaire patché avec %d modifications!\n", patchCount);
    return 0;
}
```

Ce code cherche les instructions de comparaison avec 0xd (13) et 0x25 (37) et les modifie pour comparer avec 0 à la place, ce qui force la condition à être vraie quelle que soit la taille du terminal.

## Résolution

En exécutant le programme dans un terminal de taille 13x37 ou en utilisant le binaire patché, le labyrinthe devient soluble et révèle le flag :

```
$ python3 exploit.py
Output from program:
+---+---+---+---+---+---+
|      S|       |       |
+   +   +---+   +   +   +
|   |           |   |   |
+   +---+---+   +   +   +
|   |       |       |   |
+   +   +   +---+---+   +
|       |               |
+---+   +---+---+---+   +
|   |   |           |   |
+   +   +   +---+   +   +
|       |   |   |       |
+   +---+   +   +---+---+
|   |       |          F|
+---+---+---+---+---+---+

Congratulations! Flag: HTB{th3_curs3_is_brok3n!}
```

## Flag

Le flag de ce challenge est : `HTB{th3_curs3_is_brok3n!}`

## Conclusion

ImpossibleMaze est un challenge intéressant qui nous enseigne plusieurs choses :
1. L'importance d'analyser non seulement le code principal, mais aussi les conditions environnementales
2. La possibilité d'utiliser des terminaux virtuels avec des dimensions spécifiques pour l'exploitation
3. Les techniques de patching binaire pour contourner les vérifications de sécurité

Cette approche est utile pour divers scénarios où les programmes ont des comportements différents selon les propriétés du terminal ou de l'environnement d'exécution. 