---
title: HTB Editorial Walkthrough
description: This is a Linux Machine vulnerable to SSRF. This machine is active as this was posted. Played it as a practice during my free time. The difficulty is Easy.
categories:
 - Writeup
tags:
- htb
- ssrf
- web
- linux
---

![Editorial Banner](/assets/images/htb-editorial-2024/Editorial.png)

# Enumeration Phase

Firstly, we start by enumerating the machine using NMAP and output it at a text file for easy reference later. `nmap -sV -A -p- 10.10.11.20 > nmap.txt`

![Enum1](/assets/images/htb-editorial-2024/enum1.png)

Here we see there is 2 open ports, port 22 and 80. Adding **editorial.htb** domain at **/etc/hosts** will allow us to open the web.

![Enum2](/assets/images/htb-editorial-2024/enum2.png)

Fuzzing for directory didn't show much.

![Enum3](/assets/images/htb-editorial-2024/enum3.png)
Directories found:
- /upload
- /about

# User Flag 
What caught our attention is the **/upload** page.

![Enum4](/assets/images/htb-editorial-2024/enum4.png)

Seems like we can upload book cover here or provide the url. I tried uploading web shell at the upload.

![Enum5](/assets/images/htb-editorial-2024/enum5.png)

Seems like there is a weird response `static/uploads/<random-strings>` the random strings changes everytime a request sent. So we will try to send a request without uploading any files.

![Enum6](/assets/images/htb-editorial-2024/enum6.png)

It returns **/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg**. When opening image directory in web reveals that it is a picture of the book information preview.

![Enum7](/assets/images/htb-editorial-2024/enum7.png)

Hmm maybe we can try something else. In the upload page as well, theres an alternative to put book URL. Maybe we can try Server Side Request Forgery (SSRF) here by using `http://127.0.0.1:<port>/`. We will enumerate as much port as possible

We can either use burpsuite or ffuf. Since bruteforcing 0-65535 ports in burpsuite will take forever. We will use ffuf instead.

`ffuf -u http://editorial.htb/upload-cover -X POST -request request.txt -w ports.txt -fs 61`

![Enum9](/assets/images/htb-editorial-2024/enum9.png)

The only different response is for port 5000. When requesting for port 5000 `http://127.0.0.1:5000/` we will get an interesting file. Lets download it.

![Enum11](/assets/images/htb-editorial-2024/enum11.png)

We got a few endpoints here:

![Enum10](/assets/images/htb-editorial-2024/enum10.png)

Endpoints :
- /api/latest/metadata/messages/promos
- /api/latest/metadata/messages/coupons
- /api/latest/metadata/messages/authors
- /api/latest/metadata/messages/how_to_use_platform
- /api/latest/metadata/changelog
- /api/latest/metadata

We will get login credentials at `/api/latest/metadata/messages/authors`. Download it the same way.

![Enum12](/assets/images/htb-editorial-2024/enum12.png)

Now we SSH using the credentials that we found earlier, in the home directory there is the user flag.

![User-Flag](/assets/images/htb-editorial-2024/user-flag.png)

# Root Flag

When running linpeas on the machine, we can find a **git** repository.

![Root1](/assets/images/htb-editorial-2024/root1.png)

In the directory we can use `git show <commit-id>`. 

![Root2](/assets/images/htb-editorial-2024/root2.png)

Using `git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae` will reveal the second credential for user **prod**.

![Root3](/assets/images/htb-editorial-2024/root3.png)

After we change user to prod, we can run `sudo -l` command to list sudo privileges for user prod.

![Root4](/assets/images/htb-editorial-2024/root4.png)

Seems like it has the user can run `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py` with sudo privilege.

After a few try-and-error, we found something in pip3, **GitPython 3.1.29** which has [CVE-2022-24439](https://github.com/gitpython-developers/GitPython/issues/1515). 

Equipped with this information, we can craft our own payload: 
```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/notsuspicious'
```
This will cat the root.txt and output it in /tmp/notsuspicious so that other user can read.

![Root-Flag](/assets/images/htb-editorial-2024/root-flag.png)

# Summary
This is a fun machine, but it is very do-able even for a newbie like me.

# Notes
Tools used to solve this:
- ffuf
- burpsuite

Soon...




