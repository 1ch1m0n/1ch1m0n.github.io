---
title: CyberDefenders Ramnit Walkthrough
description: Endpoint memory dump forensics using Volatility3. Feel free to read my writeup.
categories:
 - Notes
tags:
- ctf
- forensics
- volatility
- memdump
---

![CyberDefenders Banner](/assets/images/practice/cyberdefenders/cyberdefenders_banner.png)

# Details

Check out this challenge at <a href="https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/" target="_blank">Ramnit Blue Team Lab</a>

Instructions:
Uncompress the lab (pass: cyberdefenders.org) 

Scenario:
Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings. This analysis is critical in understanding the breach and preventing further compromise.

Tools:
Volatility 3

For Volatility3, I use custom alias so that I can run it easier by only using `volatiliy3` command
![Vol3](/assets/images/practice/cyberdefenders/aliasvol.png)

# Walkthrough

## Q1: We need to identify the process responsible for this suspicious behavior. What is the name of the suspicious process?

- Firstly we will look at the list of processes that were running at the infected machine. We will use `pstree` to see the parent-child process relationship so that we can identify the malicious process easier.

Command : `volatility3 -f memory.dmp windows.pstree` 
![Vol3](/assets/images/practice/cyberdefenders/q1-1.png)

- Most of the process listed are legitimate Windows system processes. These are the parent-child processes listed in order : **userinit.exe** > **explorer.exe** > **OneDrive.exe**, **SecurityHealthSysTray.exe**, **vmtoolsd.exe**, **ChromeSetup.exe**. 

- ChromeSetup.exe stands out as suspicious as it is a file that usually executed only once, but it is grouped with some of legitimate startup processes.

Answer : `ChromeSetup.exe`

## Q2: To eradicate the malware, what is the exact file path of the process executable?

- Using the same command as the previous question, we are able to see the file path of the executable. Alternatively we can use `filescan` command.

Command : `volatility3 -f memory.dmp windows.filescan | grep ChromeSetup.exe`
![Vol3](/assets/images/practice/cyberdefenders/q2-1.png)

Answer : `C:\Users\alex\Downloads\ChromeSetup.exe`

## Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What is the IP address it attempted to connect to?

- We can find the network connection associated with the suspicious process by using the `netscan` command, and then finding its PID.

Command : `volatility3 -f memory.dmp windows.netscan | grep 4628`
![Vol3](/assets/images/practice/cyberdefenders/q3-1.png)

Answer : `58.64.204.181`

## Q4: To pinpoint the geographical origin of the attack, which city is associated with the IP address the malware communicated with?

- To find the geographical origin of the attack, we can use an online tool called [Ip Address Lookup](https://www.iplocation.net/ip-lookup) which will give geolocation data of the IP Address from multiple sources.

![Vol3](/assets/images/practice/cyberdefenders/q4-1.png)

Answer : `Hong Kong`

## Q5: Hashes provide a unique identifier for files, aiding in detecting similar threats across machines. What is the SHA1 hash of the malware's executable?

- In order to get SHA1 hash of the executable, we first need to dump the suspicious process using its PID. Unlike Volatility2, Volatility3 will dump exe and its associated DLLs. Therefore to not get messy i will dump it into another directory `/dumps`

Command : `volatility3 -f memory.dmp -o ./dumps windows.dumpfiles --pid 4628`
![Vol3](/assets/images/practice/cyberdefenders/q5-1.png)

- After dumping, we will grep the file and use `sha1sum` command

Command : `sha1sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img `
![Vol3](/assets/images/practice/cyberdefenders/q5-2.png)

Answer : `280c9d36039f9432433893dee6126d72b9112ad2`

## Q6: Understanding the malware's development timeline can offer insights into its deployment. What is the compilation UTC timestamp of the malware?

- In order to retrieve the UTC Timestamp, we can use `exiftool` to extract the metadata of the file. For this question we will use the same file as before.

Command : `exiftool file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img`
![Vol3](/assets/images/practice/cyberdefenders/q6-1.png)

- Then we can see the time stamp, However we need to convert it to UTC Timestamp first. So I use ChatGPT and we will get the flag.

Answer : `2019-12-01 08:36:04`

## Q7: Identifying domains involved with this malware helps in blocking future malicious communications and identifying current possible communications with that domain in our network. Can you provide the domain related to the malware?

- We need to use the SHA1 Hash that we found earlier and submit it to [VirusTotal](https://www.virustotal.com/gui/home/upload). More details about the malicious file are on the website. Under Relations tab we will see a Domain section where the flag is. 

![Vol3](/assets/images/practice/cyberdefenders/q7-1.png)

Answer : `dnsnb8.net`

# Summary

Took some time to do this during my semester break. I hope you guys enjoy reading it. It was a fun Lab !

# Notes

Soon..

