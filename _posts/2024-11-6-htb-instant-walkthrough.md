---
title: HTB Instant Walkthrough
description: Writeup on HTB Season 6 Instant. The target is a Linux Machine in Medium Category. This machine involves decompiling an apk file and understanding how API works. The root flag also involves SolarPutty session cracking.
categories:
 - Writeup
 - HTB
tags:
- htb
- api
- web
- linux
- idor
---

![Instant Banner](/assets/img/htb-instant-2024/Instant.png)

## Enumeration

### Nmap Scan

```zsh
nmap -sV -A 10.10.11.37 -p- > nmap.txt
```

![Enum1](/assets/img/htb-instant-2024/enum1.png)

There are two open ports.
- **Port 22 (ssh)**
- **Port 80 (http)**

### Hosts File

Add this to `/etc/hosts`{: .filepath}

```bash
10.10.11.37    instant.htb
```
### Web Enumeration

 Now we can open `http://instant.htb`{: .filepath} in the browser.

![Enum2](/assets/img/htb-instant-2024/enum2.png)

Nothing interesting to see on the website itself, just a download button to download **instant.apk**. I didn't open the apk file, so what I did next is to put it at [decompiler.com](https://www.decompiler.com/) to decompile the apk.

### APK File
![Enum3](/assets/img/htb-instant-2024/enum3.png)

After decompiling we will get two folders:
- `resources`{: .filepath}
- `sources`{: .filepath}

After going through the folders, we can see that the source code is not obfuscated. There are multiple interesting files at `sources/com/instantlabs/instant`{: .filepath}.

![Enum4](/assets/img/htb-instant-2024/enum4.png)

Then I found an Authorization token in **AdminActivities.java**.<br>
**AdminActivities.java:**
```java
package com.instantlabs.instant;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class AdminActivities {
    private String TestAdminAuthorization() {
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() {
            static final /* synthetic */ boolean $assertionsDisabled = false;

            static {
                Class<AdminActivities> cls = AdminActivities.class;
            }

            public void onFailure(Call call, IOException iOException) {
                System.out.println("Error Here : " + iOException.getMessage());
            }

            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        System.out.println(JsonParser.parseString(response.body().string()).getAsJsonObject().get("username").getAsString());
                    } catch (JsonSyntaxException e) {
                        System.out.println("Error Here : " + e.getMessage());
                    }
                }
            }
        });
        return "Done";
    }
}

```

> **FINDINGS:** Seems like there's a request made to a subdomain, **mywalletv1.instant.htb** with an authorization header or JWT Token. Could be an API endpoint.
{: .prompt-tip }

We can use [JWT.io](https://jwt.io) to decode the JWT.

![Enum5](/assets/img/htb-instant-2024/enum5.png)

After this I was stuck on what to do, I tried a lot of things such as fuzzing for subdomains and directories, searching for any api endpoints vulnerabilities and more. Then as I was reading through the [Official Instant Discussion](https://forum.hackthebox.com/t/official-instant-discussion/327960), someone mentioned that there were multiple subdomains.

### Subdomains Enumeration

So the first thing I do is download the contents of the apk file. Then we can simply grep.

>**grep -rn "instant.htb" .**

![Enum6](/assets/img/htb-instant-2024/enum6.png)

Boom! we found another subdomain. **swagger-ui.instant.htb**. So we're gonna add every subdomains we found at **/etc/hosts** and open it.

![Enum7](/assets/img/htb-instant-2024/enum7.png)

> **FINDINGS:** Swagger UI allows user to visualize and interact with API's resources. In this case, we can do multiple things if we are authorized.
{: .prompt-tip }

## Finding Vulnerability

Now I'm going to authorize myself using the token we got earlier. 
![Exploit1](/assets/img/htb-instant-2024/exploit1.png)

Now that we are authorized, we can check every API, starting with **/api/v1/admin/list/users** to list out user.
![Exploit2](/assets/img/htb-instant-2024/exploit2.png)

There are two users:
- instantAdmin
- shirohige

There are other APIs but one that caught my eye is the **​/api​/v1​/admin​/view​/logs** and  **​/api​/v1​/admin​/read/logs**. These APIs can be use to read and view logs. 
![Exploit3](/assets/img/htb-instant-2024/exploit3.png)

From viewing the logs we found out that there is a log file called **1.log** and the path is located at **/home/shirohige/logs/**.
![Exploit4](/assets/img/htb-instant-2024/exploit4.png)

Now that we know the log is located in **/logs**, we can modify the path to **../user.txt** to retrieve the user flag.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2Fuser.txt" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```
### User Flag

![User-Flag](/assets/img/htb-instant-2024/user-flag.png)

### Gaining Access

To gain access to the machine, we are going to modify the playload to read **ida_rsa**. This will allow us to SSH into the machine.

![Exploit5](/assets/img/htb-instant-2024/exploit5.png)

> **NOTES:** you cannot directly copy the output, clean the key according to the actual id_rsa format. I use ChatGPT xD, you can do it manually too.

Now SSH using this command and don't forget to chmod too.

> **ssh -i id_rsa shirohige@10.10.11.37**

![Exploit6](/assets/img/htb-instant-2024/exploit6.png)

## Privilege Escalation

In order to privilege escalate, firstly I run **linpeas.sh** to see if there is any exploitable vulnerabilities. So I put my script on the server using `scp`.
>**scp -i /path/to/id_rsa linpeas.sh shirohige@10.10.11.37:/tmp**

> **NOTES:** Change the directory accordingly.

![PrivEsc1](/assets/img/htb-instant-2024/privesc1.png)

However at first I wasn't able to find anything. But reading the official Instant discussion, somebody hinted about a file called **"session"** so I filtered the output of my linpeas.

![PrivEsc2](/assets/img/htb-instant-2024/privesc2.png)

Seems like there's a Solar-Putty session data. Googling the about it i encountered [Solar PuTTY Crack](https://github.com/RainbowCache/solar_putty_crack) in github by [RainbowCache](https://github.com/RainbowCache). So I exported the file by serving a python http server and curl-ing it from my local machine. Now it's cracking time.

![PrivEsc3](/assets/img/htb-instant-2024/privesc3.png)

We need to use Visual Studio in order to compile the C# code (I'm not really familiar with it but i managed after a few try and erros). So now we can open cmd and run the executable.

![PrivEsc4](/assets/img/htb-instant-2024/privesc4.png)

I managed to crack it using **rockyou.txt** and we will get the password for root.

### Root Flag

Trying to SSH as Root didn't work. So I log in as Shirohige and `sudo su`.

![Root-Flag](/assets/img/htb-instant-2024/root-flag.png)

GGWP

![Pwned](/assets/img/htb-instant-2024/pwned.png)

## Summary
Soon..

## Notes
Tools for decompiling apk :
- jadx
- decompiler.com