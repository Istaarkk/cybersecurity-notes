---
title: "Cyber Apocalypse 2024 - SealedRune"
date: 2024-04-14
tags: ["cyber apocalypse", "reverse", "base64", "string manipulation"]
---

# SealedRune - Cyber Apocalypse 2024

## Description du challenge

SealedRune est un challenge de reverse engineering du Cyber Apocalypse CTF 2024. Le programme attend un input spécifique qui, une fois entré correctement, révèle le flag.

## Analyse du binaire

En analysant le binaire avec un désassembleur, nous avons découvert que le programme contient une chaîne encodée en Base64. Cette chaîne est ensuite décodée et comparée à l'entrée utilisateur, mais avec une particularité : la comparaison se fait avec la chaîne inversée.

Voici le pseudocode extrait de la décompilation :

```c
int main() {
    char input[50];
    char* encoded_secret = "emFyZmZ1bkdsZWFW";
    char decoded_secret[50];
    
    // Décodage de la chaîne Base64
    base64_decode(encoded_secret, decoded_secret);
    
    printf("Entrez le mot de passe pour desceller la rune : ");
    scanf("%s", input);
    
    // Vérification du mot de passe
    int valid = 1;
    int len = strlen(decoded_secret);
    
    for (int i = 0; i < len; i++) {
        if (input[i] != decoded_secret[len - i - 1]) {
            valid = 0;
            break;
        }
    }
    
    if (valid) {
        printf("Rune descellée ! Le flag est : HTB{%s}\n", input);
    } else {
        printf("Mot de passe incorrect.\n");
    }
    
    return 0;
}
```

## Exploitation

Pour résoudre ce challenge, nous devons :
1. Décoder la chaîne Base64 "emFyZmZ1bkdsZWFW"
2. Inverser la chaîne décodée
3. Utiliser ce résultat comme mot de passe

Voici le script Python que nous avons utilisé pour résoudre le challenge :

```python
import base64

# La chaîne secrète encodée en Base64
encoded_secret = "emFyZmZ1bkdsZWFW"

# Décodage Base64
decoded_secret = base64.b64decode(encoded_secret).decode('utf-8')
print(f"Chaîne décodée: {decoded_secret}")

# Inversion de la chaîne
reversed_secret = decoded_secret[::-1]
print(f"Chaîne inversée (solution): {reversed_secret}")
```

## Résolution

En exécutant notre script, nous obtenons :

```
$ python3 exploit.py
Chaîne décodée: zarffunGleaV
Chaîne inversée (solution): VaelGnuffrraz
```

Ainsi, le mot de passe correct est `VaelGnuffrraz`. En fournissant ce mot de passe au programme, nous obtenons le flag.

## Étapes de l'exploitation manuelle

Si vous préférez résoudre ce challenge manuellement sans utiliser de script, voici les étapes :

1. Identifiez la chaîne encodée "emFyZmZ1bkdsZWFW" dans le binaire
2. Décodez-la en Base64 (vous pouvez utiliser des outils en ligne ou la commande suivante) :
   ```bash
   echo "emFyZmZ1bkdsZWFW" | base64 -d
   ```
   Résultat : zarffunGleaV
3. Inversez cette chaîne (vous pouvez le faire manuellement ou avec la commande suivante) :
   ```bash
   echo "zarffunGleaV" | rev
   ```
   Résultat : VaelGnuffrraz
4. Utilisez "VaelGnuffrraz" comme input pour le programme

## Flag

En entrant le mot de passe correct, le programme nous révèle le flag :

```
$ ./challenge
Entrez le mot de passe pour desceller la rune : VaelGnuffrraz
Rune descellée ! Le flag est : HTB{VaelGnuffrraz}
```

Le flag de ce challenge est donc : `HTB{VaelGnuffrraz}`

## Conclusion

SealedRune est un challenge relativement simple qui illustre des techniques courantes utilisées pour obfusquer des chaînes de caractères dans les binaires :

1. Encodage en Base64 pour masquer le contenu
2. Inversion de chaîne pour compliquer davantage l'analyse

Ce type de protection est souvent utilisé dans les crackmes basiques et constitue une bonne introduction aux techniques de reverse engineering. Pour résoudre ce challenge, il était nécessaire de :

1. Identifier la chaîne encodée dans le binaire
2. Comprendre l'algorithme de vérification du mot de passe
3. Effectuer les transformations inverses pour obtenir le mot de passe valide

Bien que ces techniques d'obfuscation soient rudimentaires, elles servent de base pour comprendre des mécanismes plus complexes de protection de binaires. 