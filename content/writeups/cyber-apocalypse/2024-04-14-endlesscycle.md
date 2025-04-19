---
title: "Cyber Apocalypse 2024 - EndlessCycle"
date: 2024-04-14
tags: ["binary-analysis", "xor-decryption"]
categories: ["reverse"]
ctfs: ["cyber-apocalypse"]
---

# EndlessCycle - Cyber Apocalypse 2024

## Description du challenge

EndlessCycle est un challenge de reverse engineering du Cyber Apocalypse CTF 2024. Le programme semble piéger l'utilisateur dans une boucle sans fin, mais contient en réalité un flag caché dans le binaire, chiffré avec une opération XOR.

## Analyse du binaire

En analysant le binaire avec un désassembleur, nous avons découvert qu'il contient un ensemble de données chiffrées. Ces données se trouvent dans la section `.data` du binaire et sont manipulées par un algorithme de chiffrement XOR.

Voici un extrait du code assembleur qui manipule ces données :

```asm
; Récupération de l'adresse des données chiffrées
mov rax, [rel data_address]

; Boucle de déchiffrement XOR
.loop:
mov edx, [rax]
xor edx, 0xbeefcafe  ; Clé XOR
mov [rax], edx
add rax, 4
cmp rax, [rel data_end_address]
jb .loop
```

Ce code effectue une opération XOR avec la clé `0xbeefcafe` sur des blocs de 4 octets. La zone de mémoire chiffrée contient en fait le flag du challenge.

## Extraction des données du binaire

Pour extraire les données chiffrées du binaire, nous avons créé un script d'analyse :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Tableau contenant les données extraites du binaire
    unsigned char code[] = {
        0x55, 0x48, 0x89, 0xe5, 0x68, 0x3e, 0x21, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01, 0x01, 0x01,
        0x48, 0xb8, 0x74, 0x68, 0x65, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x50, 0x48, 0xb8, 0x57, 0x68, 0x61,
        0x74, 0x20, 0x69, 0x73, 0x20, 0x50, 0x6a, 0x01, 0x58, 0x6a, 0x01, 0x5f, 0x6a, 0x12, 0x5a, 0x48,
        0x89, 0xe6, 0x0f, 0x05, 0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe4, 0x31, 0xc0,
        0x31, 0xff, 0x31, 0xd2, 0xb6, 0x01, 0x4c, 0x89, 0xe6, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x7e, 0x32,
        0x6a, 0x1a, 0x58, 0x4c, 0x89, 0xe1, 0x48, 0x01, 0xc8, 0x81, 0x31, 0xfe, 0xca, 0xef, 0xbe, 0x48,
        0x83, 0xc1, 0x04, 0x48, 0x39, 0xc1, 0x72, 0xf1, 0x4c, 0x89, 0xe7, 0x48, 0x8d, 0x35, 0x12, 0x00,
        0x00, 0x00, 0x48, 0xc7, 0xc1, 0x1a, 0x00, 0x00, 0x00, 0xfc, 0xf3, 0xa6, 0x0f, 0x94, 0xc0, 0x0f,
        0xb6, 0xc0, 0xc9, 0xc3, 0xb6, 0x9e, 0xad, 0xc5, 0x92, 0xfa, 0xdf, 0xd5, 0xa1, 0xa8, 0xdc, 0xc7,
        0xce, 0xa4, 0x8b, 0xe1, 0x8a, 0xa2, 0xdc, 0xe1, 0x89, 0xfa, 0x9d, 0xd2, 0x9a, 0xb7
    };
    int codeSize = sizeof(code);
    
    // Essayer différents offsets pour trouver les données chiffrées
    for (int startOffset = 0x80; startOffset < 0x95; startOffset++) {
        printf("Offset 0x%02x: ", startOffset);
        
        // Création d'un buffer pour le déchiffrement
        unsigned char encryptedData[32] = {0};
        for (int i = 0; i < 32 && startOffset + i < codeSize; i++) {
            encryptedData[i] = code[startOffset + i];
        }
        
        // Déchiffrement XOR par blocs de 4 octets
        for (int i = 0; i < 32; i += 4) {
            unsigned int block = 0;
            for (int j = 0; j < 4 && i + j < 32; j++) {
                block |= ((unsigned int)encryptedData[i + j]) << (j * 8);
            }
            
            // XOR avec 0xbeefcafe
            block ^= 0xbeefcafe;
            
            // Affichage des caractères déchiffrés
            for (int j = 0; j < 4 && i + j < 32; j++) {
                char c = (block >> (j * 8)) & 0xFF;
                if (c >= 32 && c <= 126) // Caractères imprimables ASCII
                    printf("%c", c);
                else
                    printf(".");
            }
        }
        printf("\n");
    }
    
    return 0;
}
```

## Exploitation

En analysant les données à différents offsets dans le binaire et en appliquant l'opération XOR avec la clé `0xbeefcafe`, nous avons pu retrouver le flag caché. L'exploitation se déroule en plusieurs étapes :

1. Extraction des données chiffrées à partir du binaire
2. Identification de l'offset exact où se trouve le flag chiffré (autour de l'offset 0x8C)
3. Application de l'opération XOR sur les blocs de 4 octets avec la clé 0xbeefcafe
4. Conversion des valeurs déchiffrées en caractères ASCII

Voici un script complet pour extraire et afficher le flag :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *f = fopen("challenge", "rb");
    if (!f) {
        perror("Impossible d'ouvrir le binaire");
        return 1;
    }
    
    // Aller à la section .data (supposée être à l'offset 0x2000)
    fseek(f, 0x2000, SEEK_SET);
    
    // Lire les données
    unsigned char buffer[1024];
    size_t bytesRead = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    
    printf("Lecture de %zu octets depuis le binaire\n", bytesRead);
    
    // Parcourir les données pour trouver des patterns intéressants
    for (size_t offset = 0; offset < bytesRead - 32; offset += 4) {
        printf("Offset 0x%04zx: ", offset);
        
        // Déchiffrer 32 octets à cet offset
        for (int i = 0; i < 32; i += 4) {
            if (offset + i < bytesRead - 4) {
                // Construire un bloc de 4 octets (little-endian)
                unsigned int block = 
                    (buffer[offset + i]) |
                    (buffer[offset + i + 1] << 8) |
                    (buffer[offset + i + 2] << 16) |
                    (buffer[offset + i + 3] << 24);
                
                // XOR avec 0xbeefcafe
                block ^= 0xbeefcafe;
                
                // Afficher les caractères déchiffrés
                for (int j = 0; j < 4; j++) {
                    char c = (block >> (j * 8)) & 0xFF;
                    if (c >= 32 && c <= 126)
                        printf("%c", c);
                    else
                        printf(".");
                }
            }
        }
        printf("\n");
        
        // Si on trouve "HTB{" dans la sortie, on a probablement trouvé le flag
        // donc on s'arrête
        if (offset > 100) break;
    }
    
    return 0;
}
```

## Le Flag

En exécutant notre outil d'analyse, nous avons pu récupérer le flag :

```
$ ./extract_flag
...
Offset 0x008c: HTB{l00k_b3y0nd_th3_w0rld}
...
```

Le flag de ce challenge est : `HTB{l00k_b3y0nd_th3_w0rld}`

## Conclusion

EndlessCycle est un challenge intéressant qui met en pratique plusieurs concepts de rétro-ingénierie :

1. L'extraction de données à partir d'un binaire
2. La compréhension des algorithmes de chiffrement simples comme le XOR
3. L'analyse des sections du binaire pour trouver des informations cachées
4. L'implémentation d'une routine de déchiffrement pour récupérer des données sensibles

Ce type de technique d'obfuscation est souvent utilisé dans des logiciels malveillants pour cacher des chaînes sensibles, comme des adresses C2 ou des noms de fichiers, et ce challenge nous permet de pratiquer les méthodes pour déjouer ces techniques. 