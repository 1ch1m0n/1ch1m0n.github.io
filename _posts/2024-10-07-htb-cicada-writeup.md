---
title: HTB Cicada Writeup
description: This is one of the seasonal machine as of writing, decided to do this as a practice during my free time. This is a Windows machine and the difficulty is Easy.
categories:
 - Writeup
 - HTB
tags:
- htb
- smb
- ldap
- windows
---

![Cicada Banner](/assets/img/htb-cicada-2024/Cicada.png)


## Enumeration Phase

Firstly, we start by enumerating the machine using NMAP and output it at a text file for easy reference later. 
<br> `nmap -sV -A -p- 10.10.11.35 > nmap.txt`

![NMAP](/assets/img/htb-cicada-2024/nmap.png)

There are a few open ports here, but for now we will try looking into 445, which is the SMB port. Lets try listing the shares.
 <br> `smbclient -L //10.10.11.35`

![ENUM1](/assets/img/htb-cicada-2024/enum1.png)

Using the -N plugin, we were able to access **HR** and there seems to be a note that we can retrieve using the **GET** command.

![ENUM2](/assets/img/htb-cicada-2024/enum2.png)

The HR Note reveals a default password.

![ENUM3](/assets/img/htb-cicada-2024/enum3.png)

Since we have the default password, we only need to find a user that didn't change the default password.

After doing some research and trying for some time, I came across a tool called **NetExec**, A command-line tool used for executing commands or scripts on a remote machine over the network, often in the context of SMB shares or remote administration. 

With this tool equipped, we can continue the enumeration by bruteforcing **RIDs** to find the usernames.
<br> `netexec smb 10.10.11.35 --shares -u 'guest' -p '' --rid-brute` 

![ENUM4](/assets/img/htb-cicada-2024/enum4.png)

There are 7 usernames that were found :
- **Administrator**
- **Guest**
- **krbtgt**
- **john.smoullder**
- **sarah.dantelia**
- **michael.wrightson**
- **david.orelious**
- **emily.oscars**

When password spraying with the default password, one hits. The user **michael.wrightson** seems to be using the default password. Let see what more can we find.

![ENUM5](/assets/img/htb-cicada-2024/enum5.png)

Turns out bad since the user couldn't access most of the Shares. 

Earlier we know that the host is running LDAP service at port 389. Upon further researching on the internet, I stumbled upon [this](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap) article on HackTricks.


![ENUM6](/assets/img/htb-cicada-2024/enum6.png)

Using **ldapdomaindump** and the credentials earlier, we were able to get these.

![ENUM7](/assets/img/htb-cicada-2024/enum7.png)

When checking some of the files, we were able to get another user's password at Domain Users.

![ENUM8](/assets/img/htb-cicada-2024/enum8.png)

We found the password for David Orelious in the description. With this password we will try to access the SMB again to see if he is able to access the Shares that Michael Wrightson can't.

![ENUM9](/assets/img/htb-cicada-2024/enum9.png)

Turns he were able to access DEV. Here we see a suspicious PowerShell script called **Backup_script**. So we can download it using get.

The script has another password for the user Emily Oscars.

![ENUM10](/assets/img/htb-cicada-2024/enum10.png)

Using this credentials we can finally access the C$ Share.

![ENUM11](/assets/img/htb-cicada-2024/enum11.png)

Here we can see the structure of a normal Windows Machine.

### User Flag

When we are in the machine, the user flag is hidden at **Users\emily.oscars.CICADA\***

![USER1](/assets/img/htb-cicada-2024/user1.png)

Download it using get and cat the flag.

![USER2](/assets/img/htb-cicada-2024/user2.png)

## Exploitation Phase

Now that we are in the machine, our main goal is to escalate our privelege to root or administrator. To get a proper shell we are going to use **evil-winrm**, along with the credentials that we get earlier.

![ROOT1](/assets/img/htb-cicada-2024/root1.png)

Boom! we have a beautiful shell now, let see our privileges first.

![ROOT1.1](/assets/img/htb-cicada-2024/root1.1.png)

With a little research, we found out that the user has **SeBackupPrivilege**.
 
> **SeBackupPrivilege** allows a user to back up files, even files they wouldn’t normally have access to, including sensitive system files such as the **SAM** (Security Account Manager) database and **SYSTEM** registry hive, which can be used to extract password hashes. 
{: .prompt-info }

So I refer to [this](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) article on how to exploit it.

First we are going to save the SAM and SYSTEM reg then we are going to download it.
<br> `reg save HKLM\SAM C:\Users\emily.oscar.CICADA\Videos\sam` 
<br>`reg save HKLM\SYSTEM C:\Users\emily.oscar.CICADA\Videos\system` 

![ROOT2](/assets/img/htb-cicada-2024/root2.png)

Once downloaded, use a tool called **pypykatz** to extract the hash

![ROOT3](/assets/img/htb-cicada-2024/root3.png)

Using the hash now we can login again but this time instead of using the password we are going to use **-H** plugin for the hash.

![ROOT3.1](/assets/img/htb-cicada-2024/root3.1.png)

GG, we are in as the administrator. Now to find the flag it is located at the desktop, once you are there just cat it

### Root Flag

![ROOT4](/assets/img/htb-cicada-2024/root4.png)

## Summary
This was a very fun question indeed, I'm trying to learn more about Windows machine and I learned a lot here.

## Notes
Some commands / tools that I used for Cicada :
- evil-winrm
- crackmapexec
- netexec
- ldapsearch
- smbmap
- enum4linux-ng
- rpcclient
- smbclient
- pypykatz