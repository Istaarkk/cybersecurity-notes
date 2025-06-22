---
title: "Web Fuzzing - HTB Course WriteUp"
date: 2024-04-14
draft: false
tags: ["web", "fuzzing", "pentest", "htb"]
categories: ["web"]
---

# Web Fuzzing

Ce writeup couvre le cours **Web Fuzzing** sur HTB.

## Vue d'ensemble
Le fuzzing web est une technique essentielle en pentesting qui consiste à tester systématiquement les entrées d'une application web pour découvrir des vulnérabilités, des fichiers cachés ou des fonctionnalités non documentées.

## Premier Flag - Fuzzing de base
Pour trouver le premier flag, nous devons fuzzer le site en utilisant **Feroxbuster**, un outil open-source.
  
```bash
feroxbuster -u http://[TARGET]/FUZZ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

## Fuzzing récursif (Deuxième Flag)
Pour le fuzzing récursif (pour obtenir le deuxième flag), utilisez la commande suivante :

```bash
feroxbuster -u http://[TARGET]/recursive_fuzz -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

## Troisième Flag - Gobuster ou FFUF
HTB nous demande d'utiliser **Gobuster** pour ce flag, mais nous pouvons aussi utiliser **ffuf** :

```bash
ffuf -c -ic -t 200 -u http://[TARGET]/get.php?x=FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200
```

## Fuzzing de Virtual Host
Pour le fuzzing de virtual host, ajoutez l'hôte comme ceci :

```bash
echo '[TARGET]\tvhost.htb' | sudo tee -a /etc/hosts
```

Puis, essayez la commande suivante :

```bash
ffuf -c -ic -t 200 -u http://[TARGET] -H "Host: FUZZ.vhost.htb" -w /usr/share/wordlists/dirb/common.txt
```

## Fuzzing d'un autre hôte
Pour fuzzer un autre hôte, utilisez :

```bash
ffuf -c -ic -t 200 -u http://FUZZ.vhost.com -w /usr/share/wordlists/dns/deepmagic.com-prefixes-top50000.txt
```

## Répertoire caché (Content-Length)
Pour fuzzer un répertoire caché basé sur la longueur du contenu :

```bash
feroxbuster -u http://[TARGET] -w /usr/share/wordlists/dirb/common.txt -x .php .html .gz -t 300
```

Une fois que vous trouvez un fichier `.gz`, utilisez :

```bash
curl -I http://[TARGET]/hidden/backup.tar.gz
```

## Fuzzing d'API
Utilisez **ffuf** pour le fuzzing d'API :

```bash
ffuf -c -ic -t 200 -w /usr/share/wordlists/dirb/common.txt -u http://[TARGET]/FUZZ -mc 200
```

Puis utilisez **curl** :

```bash
curl http://[TARGET]/endpoint
```

## Étape finale (Trouver le Panel)
Pour l'étape finale, utilisez :

```bash
feroxbuster -u http://[TARGET] -w /usr/share/wordlists/dirb/common.txt -x .php .html -t 300
```

Une fois que vous trouvez un panel, utilisez **ffuf** :

```bash
ffuf -c -ic -t 200 -w /usr/share/wordlists/dirb/common.txt -u http://[TARGET]/admin/panel.php?accessID=FUZZ -mc 200 -fs 58
``` 