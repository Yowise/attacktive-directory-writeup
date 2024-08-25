🔗 Link to the challenge: [](https://tryhackme.com/r/room/attacktivedirectory)
🟠 Difficulty: Medium
⚙️ Tools used: nmap, enum4linux, Impacket(GetNPUsers.py, secretsdump.py), Kerbrute, hidra, smbclient, smbmap, smbget, cyberchef, Evil-WinRM 
🧑‍💻 Techniques: enumeration, exploitation, domain privilege escalation
🟢 State of the write-up: Final


#### Welcome to a new challenge from TryHackMe. Today I decided to learn how to attack Active Directory and I consider that this challenge was a great exercise. I practiced on tools already known as well as on tools that I did not know about before.


1. Run an nmap scan
 command used: nmap -sV $Target_IP
                -sV is a flag used for Service/ version detection. It probes on open ports to determine service/ version info

