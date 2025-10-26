---
title: "Cyber Apocalypse 2024 - SealedRune"
date: 2024-04-14
tags: ["reverse", "binary-analysis", "decompilation"]
categories: ["reverse"]
ctfs: ["cyber-apocalypse"]
---

# SealedRune - Cyber Apocalypse 2024

## Challenge Description

SealedRune is a reverse engineering challenge from Cyber Apocalypse CTF 2024. The program expects a specific input which, when entered correctly, reveals the flag.

## Binary Analysis

By analyzing the binary with a disassembler, we discovered that the program contains a Base64-encoded string. This string is then decoded and compared to the user input, but with a twist: the comparison is made with the reversed string.

Here is the pseudocode extracted from the decompilation:

```c
int main() {
    char input[50];
    char* encoded_secret = "emFyZmZ1bkdsZWFW";
    char decoded_secret[50];
    
    base64_decode(encoded_secret, decoded_secret);
    
    printf("Entrez le mot de passe pour desceller la rune : ");
    scanf("%s", input);
    
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

To solve this challenge, we need to:
1. Decode the Base64 string "emFyZmZ1bkdsZWFW"
2. Reverse the decoded string
3. Use this result as the password

Here is the Python script we used to solve the challenge:

```python
import base64

encoded_secret = "emFyZmZ1bkdsZWFW"

decoded_secret = base64.b64decode(encoded_secret).decode('utf-8')
print(f"Chaîne décodée: {decoded_secret}")

reversed_secret = decoded_secret[::-1]
print(f"Chaîne inversée (solution): {reversed_secret}")
```

## Solution

```
~/HTB/Reverse/rev_sealedrune » python exploit.py                                                                                                                    
Chaîne décodée: zarffunGleaV
Chaîne inversée (solution): VaelGnuffraz

~/HTB/Reverse/rev_sealedrune » ./challenge                                                                                                                           
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠘⠃⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢠⡀⠀⢀⣤⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣷⣾⡷⠞⠛⠙⣛⣷⣤⣤⣄⡀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⢀⣤⣾⣿⣯⡁⠀⠀⠀⠀⠀⠀⠀⠀⣈⣿⣿⣦⣤⡀⠀⠀⠀⠀
       ⠀⠀⠀⢠⣾⡿⠛⠁⠀⠙⢿⡄⠀⠀⠀⠀⠀⠀⣸⡿⠋⠀⠙⠛⢿⣦⡀⠀⠀
       ⠀⠀⣴⡿⠁⠀⠀⠀⠀⠀⠈⣿⣶⣤⣀⣀⣤⣶⣿⠁⠀⠀⠀⠀⠀⠙⢿⣦⠀
       ⠀⣾⡟⠀⠀⠀⠀⠀⠀⠀⢰⡟⠉⠛⠿⠿⠛⠉⢻⡆⠀⠀⠀⠀⠀⠀⠘⣷  
       ⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⢹  
       ⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣇⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⣸⠇  
        ⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀⢰⠇⠀⠀⠀⠀⠀⠀⣰⠏    
         ⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣄⠀⠀⣀⡾⠀⠀⠀⠀⠀⣠⠞⠁    
           ⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠙⠓⠚⠋⠀⠀⠀⠀⣠⡾⠁      
              ⠙⠳⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⠖⠋        
                 ⠈⠛⠶⣤⣄⡀⠀⠀⢀⣠⡤⠖⠛⠁          
                     ⠉⠛⠛⠉
🔮 The ancient rune shimmers with magical energy... 🔮
Enter the incantation to reveal its secret: VaelGnuffraz
The rune glows with power... The path to The Dragon’s Heart is revealed!
The secret spell is `HTB{run3_m4g1c_r3v34l3d}`.
```

By entering the correct password, the program reveals the flag.

## Flag

`HTB{run3_m4g1c_r3v34l3d}`

