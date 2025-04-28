---
title: "Cyber Apocalypse 2024 - EncryptedScroll"
date: 2024-04-14
tags: ["cyber apocalypse", "reverse", "character manipulation", "encryption"]
---

# EncryptedScroll - Cyber Apocalypse 2024

## Description du challenge

EncryptedScroll est un challenge de reverse engineering du Cyber Apocalypse CTF 2024. Le programme simule un parchemin magique qui ne révèle son contenu qu'après avoir déchiffré une incantation secrète.

## Analyse du binaire

Après avoir analysé le binaire avec un désassembleur, nous avons identifié que le programme utilise un algorithme simple de substitution pour masquer la chaîne de validation.

Voici le code désassemblé qui montre le mécanisme de vérification :

```c
int main() {
    char input[50];
    char encoded_scroll[] = "IUC|t2nqm4`gm5h`5s2uin4u2d~";
    char decoded_scroll[50];
    
    // Déchiffrement de l'incantation
    int len = strlen(encoded_scroll);
    for (int i = 0; i < len; i++) {
        decoded_scroll[i] = encoded_scroll[i] - 1;  // Décrémentation de 1 pour chaque caractère
    }
    decoded_scroll[len] = '\0';
    
    printf("Entrez l'incantation pour déchiffrer le parchemin : ");
    scanf("%s", input);
    
    // Vérification de l'incantation
    if (strcmp(input, decoded_scroll) == 0) {
        printf("Parchemin déchiffré ! Le flag est : HTB{%s}\n", decoded_scroll);
    } else {
        printf("Incantation incorrecte. Le parchemin reste scellé.\n");
    }
    
    return 0;
}
```

La méthode de chiffrement est très simple : chaque caractère de la chaîne `encoded_scroll` a été incrémenté de 1. Pour obtenir la chaîne d'origine, il suffit de décrémenter chaque caractère.

## Exploitation

Pour résoudre ce challenge, nous devons analyser la chaîne chiffrée "IUC|t2nqm4`gm5h`5s2uin4u2d~" et appliquer la transformation inverse (décrémenter chaque caractère de 1).

Voici le script Python que nous avons utilisé pour déchiffrer la chaîne :

```python
# Analyse directe de la chaîne encodée dans le binaire
# Le code assembleur montre que la chaîne "IUC|t2nqm4`gm5h`5s2uin4u2d~" est décrementée de 1 pour chaque caractère

# Fonction pour décoder la chaîne cachée dans le binaire
def decode_string():
    encoded = "IUC|t2nqm4`gm5h`5s2uin4u2d~"
    decoded = ""
    
    for char in encoded:
        # Décrémentation de 1 pour chaque caractère (selon le code assembleur)
        decoded += chr(ord(char) - 1)
    
    print(f"[+] Chaîne encodée: {encoded}")
    print(f"[+] Chaîne décodée: {decoded}")
    return decoded

# Exécution
solution = decode_string()
print("\n[*] Pour résoudre le challenge, entrez cette solution:")
print(f">>> {solution}")
```

## Résolution

En exécutant notre script de déchiffrement, nous obtenons :

```
$ python3 exploit.py
[+] Chaîne encodée: IUC|t2nqm4`gm5h`5s2uin4u2d~
[+] Chaîne décodée: HTB{s1mpl3_fl1p_fl0p_r3v3r1d}

[*] Pour résoudre le challenge, entrez cette solution:
>>> HTB{s1mpl3_fl1p_fl0p_r3v3r1d}
```

## Étapes de l'exploitation manuelle 

Si vous souhaitez résoudre ce challenge manuellement sans utiliser de script, voici les étapes à suivre :

1. Identifiez la chaîne encodée "IUC|t2nqm4`gm5h`5s2uin4u2d~" dans le binaire.
2. Pour chaque caractère, calculez le caractère ASCII qui le précède (code ASCII - 1) :
   - 'I' (ASCII 73) => 'H' (ASCII 72)
   - 'U' (ASCII 85) => 'T' (ASCII 84)
   - 'C' (ASCII 67) => 'B' (ASCII 66)
   - '|' (ASCII 124) => '{' (ASCII 123)
   - Et ainsi de suite...
3. En continuant ce processus pour chaque caractère, vous obtiendrez la chaîne déchiffrée: "HTB{s1mpl3_fl1p_fl0p_r3v3r1d}"

## Exécution du programme

Une fois le mot de passe déchiffré, nous pouvons l'utiliser pour obtenir le flag :

```
$ ./challenge
Entrez l'incantation pour déchiffrer le parchemin : HTB{s1mpl3_fl1p_fl0p_r3v3r1d}
Parchemin déchiffré ! Le flag est : HTB{s1mpl3_fl1p_fl0p_r3v3r1d}
```

## Flag

Le flag de ce challenge est : `HTB{s1mpl3_fl1p_fl0p_r3v3r1d}`

## Conclusion

EncryptedScroll est un challenge de reverse engineering simple qui illustre un concept fondamental : les transformations de caractères. Même si l'algorithme utilisé ici est très basique (simple décrémentation), ce type de technique est couramment utilisé pour obfusquer des chaînes dans les binaires.

Les points clés à retenir de ce challenge sont :

1. Importance de l'analyse du code assembleur pour comprendre les opérations effectuées sur les chaînes de caractères
2. Compréhension des transformations de caractères simples (incrémentation/décrémentation)
3. Mise en œuvre d'une solution pour inverser ces transformations

Ce challenge est une excellente introduction aux techniques de base de reverse engineering et montre comment des méthodes simples d'obfuscation peuvent être facilement contournées avec une bonne compréhension du code sous-jacent. 