---
title: "FCSC 2024 - Challenge de Reverse Engineering"
date: 2024-04-27
tags: ["reverse", "reverse-engineering", "assembly", "cryptography"]
categories: ["reverse"]
ctfs: ["fcsc"]
---

# Write-up: Challenge de Reverse Engineering

## Introduction
Ce write-up présente la résolution d'un challenge de reverse engineering où nous devions analyser du code assembleur pour trouver un flag au format FCSC{...}.

## Analyse du code
Le code fourni est une représentation désassemblée d'un programme binaire. En analysant les fonctions principales, nous avons pu comprendre le fonctionnement général du programme:

1. `main()` initialise le programme et déchiffre trois chaînes de caractères en effectuant un XOR avec des constantes (0x42, 0x13, 0x37)
2. Le programme obtient une entrée utilisateur via `VsvYbpipYYgRoCeFtoxhtAmdFuNu3WvV()`
3. Cette entrée est transformée par `wKtyPoT4WdyrkVzhvYUfvqo3M9iPVMd3()`
4. Le résultat est comparé avec une valeur cible (`jMunhwoW4bRqeCdJfXvfNrRm`) dans `VakkEeHbtHMpNqXPMkadR4v7K()`

## Le mécanisme de chiffrement
La fonction clé est `wKtyPoT4WdyrkVzhvYUfvqo3M9iPVMd3()` qui transforme l'entrée utilisateur comme suit:
```
char rax_3 = *(sx.q(i) + &aixxj3qmUvFTqgqLodmuaEap)
*(sx.q(i) + &U94y77bvL3HfcnwcAc3UA9MJTvcwjP4j) = (i.b * 3 + 0x1f) ^ (rax_3 << 3 | rax_3 s>> 5)
```

Pour chaque caractère de l'entrée:
1. Une clé est calculée comme `(index * 3 + 0x1f)`
2. Le caractère est décalé (`(rax_3 << 3 | rax_3 s>> 5)`)
3. La clé et le caractère décalé sont combinés par XOR

## Données importantes
Grâce aux données supplémentaires fournies, nous avons pu extraire:
- La valeur cible `jMunhwoW4bRqeCdJfXvfNrRm` à l'adresse `0x4020`
- Les messages chiffrés pour l'invite, le succès et l'échec

La valeur de `jMunhwoW4bRqeCdJfXvfNrRm` en hexadécimal:
```
2d 38 bf 32 f0 05 a8 b5 04 9b 8c 53 ca e7 f0 67 f6 59 c4 f1 50 e7 7a a5 
74 ab dc d9 50 f7 5a bd b6 2b 9e 31 90 37 08 1d 3e a9 2c 69 0a 67 38 9f 
0e 2b 24 93 72 1f 40 6d d4 7b ee 51 1a 4f ca 6d ec f1 24 cb 72 05 f1
```

## Solution: Reverse engineering de l'algorithme
Pour résoudre ce challenge, nous avons créé un script qui inverse l'algorithme de chiffrement:

```python
def decrypt_char(encrypted_byte, index):
    key = (index * 3 + 0x1f) & 0xFF
    
    # Essayer tous les caractères possibles
    for c in range(32, 127):  # Plage ASCII imprimable
        shifted = ((c << 3) | (c >> 5)) & 0xFF
        if (key ^ shifted) == encrypted_byte:
            return chr(c)
    return '?'  # Si aucun caractère valide n'est trouvé

# La valeur hexadécimale de jMunhwoW4bRqeCdJfXvfNrRm
encrypted_bytes = [
    0x2d, 0x38, 0xbf, 0x32, 0xf0, 0x05, 0xa8, 0xb5, 
    0x04, 0x9b, 0x8c, 0x53, 0xca, 0xe7, 0xf0, 0x67, 
    0xf6, 0x59, 0xc4, 0xf1, 0x50, 0xe7, 0x7a, 0xa5, 
    0x74, 0xab, 0xdc, 0xd9, 0x50, 0xf7, 0x5a, 0xbd, 
    0xb6, 0x2b, 0x9e, 0x31, 0x90, 0x37, 0x08, 0x1d, 
    0x3e, 0xa9, 0x2c, 0x69, 0x0a, 0x67, 0x38, 0x9f, 
    0x0e, 0x2b, 0x24, 0x93, 0x72, 0x1f, 0x40, 0x6d, 
    0xd4, 0x7b, 0xee, 0x51, 0x1a, 0x4f, 0xca, 0x6d,
    0xec, 0xf1, 0x24, 0xcb, 0x72, 0x05, 0xf1
]

flag = ""
for i, byte in enumerate(encrypted_bytes):
    flag += decrypt_char(byte, i)

print("Flag déchiffré:", flag)
```

Pour chaque octet chiffré, nous cherchons le caractère original qui, une fois transformé par l'algorithme, produirait l'octet chiffré.

## Résultat
L'exécution du script nous a permis d'obtenir le flag:
```
FCSC{e30f46b147e7a25a7c8b865d0d895c7c7315f69582f432e9405b6d093b6fb8d3}
```

## Conclusion
Ce challenge était un exemple typique de reverse engineering où il fallait:
1. Comprendre le flux du programme
2. Identifier l'algorithme de chiffrement/transformation
3. Extraire les données importantes (la valeur cible)
4. Inverser l'algorithme pour récupérer le flag

La difficulté principale résidait dans la compréhension précise de l'algorithme de transformation et dans l'extraction correcte des données hexadécimales à partir du code désassemblé. 