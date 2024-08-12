---
title: rawSEC rENTAS 2024 CTF Writeup
description: On the 9th March 2024, I participated in rENTAS CTF held at Universiti Tenaga Nasional (UNITEN), Putrajaya. I was a part of team R3BUNG which consist of Abdullah, Munir and Akif (Me). Alhamdulillah we managed to get the 7th place in the Final round. Here is my part of the writeup.
categories:
 - Writeup
tags:
- ctf
- dfir
- osint
- crypto
- network
---

![RENTAS Banner](/assets/images/rentas-ctf-2024/rawSEC.png)


<!-- more -->

<div style="text-align: center;">
    <p style="font-size: 24px; font-weight: bold">Challenges</p>
</div>

# Qualifying Round

The qualifying round consists of multiple categories, but I only managed to get 2 OSINT and Crypto challenges.

## OSINT
### Cali Cartel

This question is very straightforward, as the description stated “knowledge is power” suggests that the flag is somewhere on the internet. A simple google search using Google search operator Cali Cartel “RWSC” reveals that the flag is in a Reddit website.

![cali1](/assets/images/rentas-ctf-2024/calicartel-1.png)

```
Flag: RWSC{C4L1_C4RT3L_PWN3D}
```

### Medellin Cartel

This one is quite tricky, but when the clue was released it led us to an Instagram profile `@nelsonhernandez144` which the clue tells us something about the metadata

![medellin1](/assets/images/rentas-ctf-2024/medellincartel-1.png)

Using a tool called `Instaloader` we were able to extract this profile along with its metadata. Further check on each of the files reveals that the flag is in one of the .json documents.

![medellin2](/assets/images/rentas-ctf-2024/medellincartel-2.png)

![medellin3](/assets/images/rentas-ctf-2024/medellincartel-3.png)

```
Flag: RWSC{Bl4cky_S1c4r10}
```

## Cryptography
### round and round 

This one took us a while to figure it out, in the end the clue lies within the description “I love to eat pizza”. Upon further googling we found one cipher named Pizzini Cipher, from there on everything was so direct.

![rnr1](/assets/images/rentas-ctf-2024/roundnround-1.png)

```
Flag: RWSC{PIZZINI_CIPHER_WAS_EAZY}
```

# Final Round
The questions are definitely harder than the qualifying. However I only managed to get a few flags.

## DFIR
### Hiding Zombie

![hiding0](/assets/images/rentas-ctf-2024/hidingzombie-0.png)

Firstly we were given a corrupted .png file

![hiding1](/assets/images/rentas-ctf-2024/hidingzombie-1.png)

Upon checking the picture using `pngcheck` we can see there are errors in the picture. We solve the CRC error by replacing `7f1d2b83` with `80d35286` , so that we can open the picture.

![hiding2](/assets/images/rentas-ctf-2024/hidingzombie-2.png)

![hiding3](/assets/images/rentas-ctf-2024/hidingzombie-3.png)

Then we uploaded the picture to a website called `FotoForensics` and analyse the picture using Hidden Pixels.

![hiding4](/assets/images/rentas-ctf-2024/hidingzombie-4.png)

```
Flag: RWSC{z0mb13_4tt4ck_1nc0m1ng}
```

## Hardware 
### 7 Segment 4 Digit

This is a very interesting physical question, we were presented with a 7 segment LCD display and an Arduino board in which we need to light up by connecting wires on the board. Surprisingly we managed to connect it and got first blood for the Hardware category as we were picked to do it first thing in the morning as the CTF Event started. Upon successfull connection it will display the flag.

![hardware1](/assets/images/rentas-ctf-2024/hardware-1.jpg)

```
Flag: RWSC{1337}
```
## Network
### I Hope You Have The Software

![software0](/assets/images/rentas-ctf-2024/ihopeuhavesoftware-0.png)

This question is rather a straightforward one, firstly when we opened the file in Cisco Packet Tracer we check what is in the server and there is a suspicious sampleFile.txt

![software1](/assets/images/rentas-ctf-2024/ihopeuhavesoftware-1.png)

However upon further checking there is nothing here, the real clue lies within each services of the server running. By checking each of the server’s services patiently, we came across the flag inside index.html

![software2](/assets/images/rentas-ctf-2024/ihopeuhavesoftware-2.png)

When we opened it and scroll down BOOM! the flag was there.

![software3](/assets/images/rentas-ctf-2024/ihopeuhavesoftware-3.png)

```
Flag: RWSC{_t4c3r_f!l3_:D!t5_a}
```
