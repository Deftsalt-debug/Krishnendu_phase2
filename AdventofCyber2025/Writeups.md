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

## Flag
```
Pwned by HopSec
3aster_
15_th3_
n3w_xm45
3306
THM{4ll_s3rvice5_d1sc0vered}
```



