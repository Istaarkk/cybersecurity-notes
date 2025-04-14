---
title: "Web Fuzzing - HTB Course WriteUp"
date: 2024-04-14
draft: false
tags: ["web", "fuzzing", "pentest", "htb"]
---

# Web Fuzzing

These writeups cover the **Web Fuzzing** course on HTB.

## Overview
These writeups cover the **Web Fuzzing** course on HTB.

## First Flag
- To find the first flag, we need to fuzz the site `http://address/FUZZ` using **Feroxbuster**, an open-source tool.
  
    ```bash
    feroxbuster -u http://94.237.61.202:58637/FUZZ -w /root/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
    ```

## Recursive Fuzzing (Second Flag)
- For recursive fuzzing (to get the second flag), use the following command:

    ```bash
    feroxbuster -u http://94.237.61.202:58637/recursive_fuzz -w /root/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
    ```

## Third Flag - Gobuster or FFUF
- HTB asks us to use **Gobuster** for this flag, but we can also use **ffuf**:

    ```bash
    ffuf -c -ic -t 200 -u http://83.136.251.168:55827/get.php?x=FUZZ -w /root/SecLists/Discovery/Web-Content/common.txt -mc 200
    ```

## Vhost Fuzzing
- For virtual host fuzzing, add the host like this:

    ```bash
    echo '94.237.61.202:39228\tinlanefreight.htb' | sudo tee -a /etc/hosts
    ```

- Then, try the following command:

    ```bash
    ffuf -c -ic -t 200 -u http://94.237.61.202:39228 -H "Host: FUZZ.inlanefreight.htb" -w /root/SecLists/Discovery/Web-Content/common.txt
    ```

- Results:

    ```bash
    ADMIN [Status: 200, Size: 100, Words: 4, Lines: 2, Duration: 31ms]
    Admin [Status: 200, Size: 100, Words: 4, Lines: 2, Duration: 34ms]
    admin [Status: 200, Size: 100, Words: 4, Lines: 2, Duration: 19ms]
    awmdata [Status: 200, Size: 104, Words: 4, Lines: 2, Duration: 22ms]
    ipdata [Status: 200, Size: 102, Words: 4, Lines: 2, Duration: 15ms]
    web-beans [Status: 200, Size: 108, Words: 4, Lines: 2, Duration: 15ms]
    ```

## Fuzzing another host
- To fuzz another host, use:

    ```bash
    ffuf -c -ic -t 200 -u http://FUZZ.inlanefreight.com -w /root/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
    ```

## Hidden Directory (Content-Length)
- To fuzz for a hidden directory based on content length:

    ```bash
    feroxbuster -u http://83.136.254.23:31915 -w /root/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php .html .gz -t 300
    ```

- Once you find a `.gz` file, use:

    ```bash
    curl -I http://83.136.254.23:31915/ur-hiddenmember/backup.tar.gz
    ```

- This will give you the correct content length (22/28).

## API Fuzzing
- Use **ffuf** for API fuzzing:

    ```bash
    ffuf -c -ic -t 200 -w /root/SecLists/Discovery/Web-Content/common.txt -u http://94.237.51.84:37078/FUZZ -mc 200
    ```

- Then use **curl**:

    ```bash
    curl http://94.237.51.84:37078/czcmdcvt
    ```

## Final Step (Finding the Panel)
- For the final step, use:

    ```bash
    feroxbuster -u http://83.136.254.23:50543 -w /root/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php .html -t 300
    ```

- Once you find a panel, use **ffuf**:

    ```bash
    ffuf -c -ic -t 200 -w /root/SecLists/Discovery/Web-Content/common.txt -u http://83.136.254.23:50543/admin/panel.php?accessID=FUZZ -mc 200 -fs 58
    ```

- You will find `getaccess`, which gives you a new host to fuzz. 