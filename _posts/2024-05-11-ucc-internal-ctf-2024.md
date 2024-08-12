---
title: UCC Internal CTF Commando 2024 (Network)
description: This is my first time ever participating in a CTF as the challenge creator for UiTM Shah Alam 's first ever internal CTF. Feel free to read this amazing experience and also my official writeup.
categories:
 - Writeup
tags:
- ctf
- network
- cisco
- wireshark
- routing
- switching
---

![Commando Banner](/assets/images/ucc-ctf-2024/UccCommando.png)

<!-- more -->

# First Challenge Creator Experience !

![UCC SOC](/assets/images/ucc-ctf-2024/random1.jpg)

Hello Everyone, about a month ago on 21st April 2024 I was given the opportunity to be one of the challenge creators for UiTM Cyberheroes Club Internal CTF 2024. I was selected to create the challenge for the Network Category. Therefore I use my little knowledge as a Network Student to create 3 Network questions which used Wireshark and Cisco Packet Tracer. Therefore this is my official Writeup of the challenges! Happy reading !

# Challenges

## Your First Network ^-^

![Chall1](/assets/images/ucc-ctf-2024/chal1.png)

<p>
  Download the challenge 
  <a href="https://drive.google.com/file/d/1dDdqyJR0Eb7FjoFJg5HZFewCq9sGLvMQ/view?usp=drive_link" target="_blank">here</a>
</p>

This is the first network category question, participants are required to use Cisco Packet Tracer in order to open the .pka file and solve the challenge

Device Configuration :

| Device | Interface | IP Address | Subnet Mask |
| --- | --- | --- | --- |
| S1 | VLAN 1 | 192.168.1.253 | 255.255.255.0 |
| S2 | VLAN 1 | 192.168.1.254 | 255.255.255.0 |
| PC1 | NIC | 192.168.1.1 | 255.255.255.0 |
| PC2 | NIC | 192.168.1.2 |  255.255.255.0 |

Before I do any configuration, I usually connect the cable to each devices first, and rename everything according to the Device Configuration. It doesn't matter which interface you connected the cable to.

![Chall1-1](/assets/images/ucc-ctf-2024/chal1-1.png)

Now the for the fun part, which is the configuration. First we are going to set up the IP addresses for each devices, we will start with the PCs. To configure the IP address for the PC, just click on the PC and go to Desktop > IP Configuration. A window like this will appear.

![Chall1-2](/assets/images/ucc-ctf-2024/chal1-2.png)

Then fill out the the IPv4 Address and the subnet mask field. After completing this, your completion should be at 16%.

![Chall1-3](/assets/images/ucc-ctf-2024/chal1-3.png)

Next we will configure the hostname and the IP addresses for each Switch using the CLI. The commands are as below :

```bash
Switch0> enable
Switch0# configure terminal
Switch0(config)# hostname S1
S1(config)# int vlan 1
S1(config-if)# ip address 192.168.1.253 255.255.255.0
S1(config-if)# no shutdown
```
Do the same for S2 and adjust the IP address and subnet mask accordingly. After you complete this you will get 100% completion.

![Chall1-4](/assets/images/ucc-ctf-2024/chal1-4.png)

Clicking check results will reveal the flag.

![Chall1-flag](/assets/images/ucc-ctf-2024/chal1-flag.png)

```
Flag : UCC{l4y3r2_b45ic}
```

## Secret Message

![Chall2](/assets/images/ucc-ctf-2024/chal2.png)

<p>
  Download the challenge 
  <a href="https://drive.google.com/file/d/1HTi7WVS3JxcgCAMg73uAR0-YX_p3uKx2/view?usp=drive_link" target="_blank">here</a>
</p>

For the second challenge, the participant was presented with packet capture or PCAP file. In which they are required to analyse the traffic.

This challenge is a little bit tricky, but a straightforward one. Upon opening the files, participants are presented with 177 packets. There are two main traffic here which is FTP and DNS.

![Chall2-1](/assets/images/ucc-ctf-2024/chal2-1.png)

As we can see, the FTP stated that a file called secret.txt was stored, so we can export the FTP-Data to get the `secret.txt`.

![Chall2-2](/assets/images/ucc-ctf-2024/chal2-2.png)

However the secret.txt was a rabbit hole xD. It is a ROT-13 encrypted message and there is no flag here, but it holds the clue to the real flag which is located "somewhere it won't be block". This refers to the DNS traffic, as DNS traffic is not often blocked unless there are a certain circumstances.

![Chall2-3](/assets/images/ucc-ctf-2024/chal2-3.png)

Looking at the DNS traffic, we saw a suspicious text at the domain of the website, it is Base32-encrypted, however is it split into many parts

![Chall2-4](/assets/images/ucc-ctf-2024/chal2-4.png)

Extracting it manually one-by-one will be a long process, therefore we will use Tshark instead, run the following command extract the Base32 code :

```bash
sudo tshark -nr ~/Desktop/chall3.pcapng -Y "(dns && dns.qry.name contains \"uitm\" && ip.src == 192.168.213.128)" | awk '{print $12}' | awk -F'.' '{print $1}' | uniq
```

We will get the following output, then throw it into the Cyberchef and apply From Base32 and Unzip filter to reveal the flag

![Chall2-5](/assets/images/ucc-ctf-2024/chal2-5.png)

![Chall2-6](/assets/images/ucc-ctf-2024/chal2-6.png)

```bash
Flag : UCC{dn5_3xf1ltr4ti0n}
```

## Mr. Ocin's Problem

![Chall3](/assets/images/ucc-ctf-2024/chal3.png)

<p>
  Download the challenge 
  <a href="https://drive.google.com/file/d/1ITlFD0rbRPj0SBH-NwVyY585zwVKTjwp/view?usp=drive_link" target="_blank">here</a>
</p>

This is yet another packet tracer challenge, however this one might be very hard if you are not familiar with Routing and Switching Protocols.

Device Configuration :

| Device | Interface | IP Address | Subnet Mask | Default Gateway |
| --- | --- | --- | --- | --- |
| ISP | G0/0/0 | 10.0.0.1 | 255.255.255.0 | - |
|     | G0/0/1 | 10.0.1.1 | 255.255.255.0 | - |
| Home Router | G0/0/0 | 10.0.0.2 | 255.255.255.0 | - |
|  | G0/0/1 | 192.16.1.1 | 255.255.255.0 | - |
| Office Router | G0/0/0 | 10.0.1.2 | 255.255.255.0 | - |
|  | G0/0/1 | 172.16.1.1 | 255.255.255.0 | - |
| My PC | NIC | 192.168.1.10 | 255.255.255.0 | 192.168.1.1 |
| Server | NIC | 172.16.1.10 |  255.255.255.0 | 172.16.1.1 |

For this challenge there are 3 errors on the network, IP Configuration of My PC, No routing protocols on Home Router, ACL on Office Router blocking all traffic from my PC

Firstly I changed the IP of My PC, make sure it is correct. Then we can start applying routing protocols for the Home Router, there are a lot but I will use Open Shortest Path First (OSPF) for this one. The command are as below:

```bash
HomeRouter# enable
HomeRouter# configure terminal
HomeRouter(config)# router ospf 10
HomeRouter(config-router)# network 10.0.0.0 0.0.0.255 area 0
S1(config-if)# network 192.168.1.0 0.0.0.255 area 0
S1(config-if)# end
```
![Chall3-1](/assets/images/ucc-ctf-2024/chal3-1.png)

This command will run OSPF on the router so that it could establish adjacency or connect to the Office Network which is also running OSPF.

Next we will look into the ACL that had been configured on Office Router. On every network device, we can run "show run" command to see every configuration on the device. So that's the first thing we're going to do.

![Chall3-2](/assets/images/ucc-ctf-2024/chal3-2.png)

There are a lot of configurations, but the one that we want to focus on is the access list (ACL) configurations. The config block all traffic from the host 192.168.1.10 to the network 172.16.1.0 , Therefore we need to disable it in order to make the Server reachable from My PC. Run the following command :

```bash
OfficeRouter# enable
OfficeRouter# configure terminal
OfficeRouter(config)# no access-list 101 deny ip host 192.168.1.10 172.16.1.0 0.0.0.255
```
We can verify the network connectivity from My PC to Server using ping command. Successful ping means the network is good to go.

![Chall3-3](/assets/images/ucc-ctf-2024/chal3-3.png)

Next we can retrieve the file from the server, connect to the Server from My PC using ftp. Login using admin admin.

![Chall3-4](/assets/images/ucc-ctf-2024/chal3-4.png)

As we can see, when running dir command, there are flag.txt. Use get to retrieve it then it is complete!. The completion will be 100% and the flag is on check results but it is in Base64. Putting in into Cyberchef will reveal the flag.

![Chall3-flag](/assets/images/ucc-ctf-2024/chal3-flag.png)

```bash
Flag : UCC{n3tw0rk_i5_3a5y}
```

# Summary

![Catmeme](/assets/images/ucc-ctf-2024/random2.png)

This was a very fun experience indeed, But I think theres a lot of room to improve. Sorry too to all non-network students xD as this question might be a little tough for you. That's all from me, thank you for reading !