---
title: "Cyber Apocalypse 2024 - EncryptedScroll"
date: 2024-04-14
tags: ["cyber apocalypse", "reverse", "character manipulation", "encryption"]
---

# EncryptedScroll - Cyber Apocalypse 

## Challenge Description

EncryptedScroll is a reverse engineering challenge from Cyber Apocalypse CTF 2024. The program simulates a magical scroll that only reveals its content after entering a secret incantation.

## Binary Analysis

After analyzing the binary with a disassembler, we identified that the program uses a simple substitution algorithm to hide the validation string.

Here is the decompiled code showing the verification mechanism:

```c
int main() {
    char input[50];
    char encoded_scroll[] = "IUC|t2nqm4`gm5h`5s2uin4u2d~";
    char decoded_scroll[50];
    int len = strlen(encoded_scroll);
    for (int i = 0; i < len; i++) {
        decoded_scroll[i] = encoded_scroll[i] - 1;
    }
    decoded_scroll[len] = '\0';
    printf("Enter the incantation to decrypt the scroll: ");
    scanf("%s", input);
    if (strcmp(input, decoded_scroll) == 0) {
        printf("Scroll decrypted! The flag is: HTB{%s}\n", decoded_scroll);
    } else {
        printf("Incorrect incantation. The scroll remains sealed.\n");
    }
    return 0;
}
```

The encoding method is very simple: each character of the `encoded_scroll` string is incremented by 1. To get the original string, just decrement each character.

## Solution

The binary hides the flag by encoding a string: each character is incremented by 1. To recover the flag, simply decrement each character by 1. Here is a minimal Python script to solve the challenge:

```python
def decode_string():
    encoded = "IUC|t2nqm4`gm5h`5s2uin4u2d~"
    decoded = ""
    for char in encoded:
        decoded += chr(ord(char) - 1)
    print(f"[+] Encoded string: {encoded}")
    print(f"[+] Decoded string: {decoded}")
    return decoded

solution = decode_string()
print("\n[*] To solve the challenge, enter this solution when prompted:")
print(f">>> {solution}")
```

**Manual exploitation steps:**
1. Run the binary: `./challenge`
2. When prompted, enter the decoded string above.
3. The flag will be displayed.

---

## Automated Exploit (pwntools)

If you want to automate the process using pwntools:

```python
from pwn import *

encoded = "IUC|t2nqm4`gm5h`5s2uin4u2d~"
decoded = ''.join([chr(ord(c)-1) for c in encoded])

p = process('./challenge')
p.recvuntil(b": ")
p.sendline(decoded.encode())
print(p.recvall().decode())
```

This script launches the binary, waits for the prompt, sends the decoded string, and prints the output (including the flag).

## Flag

The flag for this challenge is: `HTB{s1mpl3_fl4g_4r1thm3t1c}`
