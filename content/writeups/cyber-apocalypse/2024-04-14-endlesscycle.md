---
title: "Cyber Apocalypse 2024 - EndlessCycle"
date: 2024-04-14
tags: ["reverse", "binary-analysis", "xor-decryption"]
categories: ["reverse"]
ctfs: ["cyber-apocalypse"]
---

# EndlessCycle - Cyber Apocalypse

## Challenge Description

EndlessCycle is a reverse engineering challenge from Cyber Apocalypse CTF 2024. The program appears to trap the user in an endless loop, but actually contains a flag hidden in the binary, encrypted with a XOR operation.

## Binary Analysis

By analyzing the binary with a disassembler, we discovered it contains a set of encrypted data. These data are located in the `.data` section of the binary and are manipulated by a XOR encryption algorithm.

Here is an excerpt of the assembly code that handles these data:

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

This code performs a XOR operation on 4-byte blocks. The encrypted memory area actually contains the challenge flag.

## Extracting Data from the Binary

To extract the encrypted data from the binary, we created an analysis script:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
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
    
    for (int startOffset = 0x80; startOffset < 0x95; startOffset++) {
        printf("Offset 0x%02x: ", startOffset);
        
        unsigned char encryptedData[32] = {0};
        for (int i = 0; i < 32 && startOffset + i < codeSize; i++) {
            encryptedData[i] = code[startOffset + i];
        }
        
        for (int i = 0; i < 32; i += 4) {
            unsigned int block = 0;
            for (int j = 0; j < 4 && i + j < 32; j++) {
                block |= ((unsigned int)encryptedData[i + j]) << (j * 8);
            }
            
            block ^= 0xbeefcafe;
            
            for (int j = 0; j < 4 && i + j < 32; j++) {
                char c = (block >> (j * 8)) & 0xFF;
                if (c >= 32 && c <= 126) 
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

By analyzing the data at different offsets in the binary and applying the XOR operation with the key `0xbeefcafe`, we were able to recover the hidden flag. The exploitation proceeds in several steps:

1. Extracting the encrypted data from the binary
2. Identifying the exact offset where the encrypted flag is located (around offset 0x8C)
3. Applying the XOR operation on 4-byte blocks with the key 0xbeefcafe
4. Converting the decrypted values to ASCII characters

Here is a complete script to extract and display the flag:

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
    
    fseek(f, 0x2000, SEEK_SET);
    
    unsigned char buffer[1024];
    size_t bytesRead = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    
    printf("Lecture de %zu octets depuis le binaire\n", bytesRead);
    
    for (size_t offset = 0; offset < bytesRead - 32; offset += 4) {
        printf("Offset 0x%04zx: ", offset);
        
        for (int i = 0; i < 32; i += 4) {
            if (offset + i < bytesRead - 4) {
                unsigned int block = 
                    (buffer[offset + i]) |
                    (buffer[offset + i + 1] << 8) |
                    (buffer[offset + i + 2] << 16) |
                    (buffer[offset + i + 3] << 24);
                
                block ^= 0xbeefcafe;
                
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
        

        if (offset > 100) break;
    }
    
    return 0;
}
```

## The Flag

By executing our analysis tool, we were able to retrieve the flag:

```
$ ./extract_flag
...
Offset 0x008c: HTB{l00k_b3y0nd_th3_w0rld}
...
```

The flag for this challenge is: `HTB{l00k_b3y0nd_th3_w0rld}`

