# bc_wifi_attack
BeCode Module - Wifi Attacks

## What is a Wifi network penetration test?
Before the advent of Wi-Fi, hackers had two types of computer attacks at their disposal. They could either use an external attack, via the Internet, or an internal attack, by accessing the company's internal network through a malicious person or a ruse.

Thanks to wireless, a hacker can access the network without having to enter the premises. Wireless network pentesting consists in searching for vulnerabilities in the entire wireless infrastructure of the company. Whether it is a simple "box" or a complex configuration, the Wifi penetration test will highlight possible weaknesses in the system that could be exploited by a malicious person.

## Why a Wifi network pentest?
The Wifi network opens an additional door to the hacker. While the wired network "stops" at the walls of the company and is not accessible from outside, the Wi-Fi network can be visible outside the company. Depending on the power, positioning and configuration of the wireless network equipment, it is possible to detect a company's Wi-Fi network by standing close enough, while remaining outside. The hacker does not need to have physical access to the company, he just needs to be able to stand close enough. This can be complicated in a factory surrounded by a large security perimeter, but particularly easy in an office building shared by several companies or a health care facility, for example.

An insufficiently secured wireless network can allow a hacker to connect to the corporate network. Once inside the system, it will be possible to take advantage of other vulnerabilities, inherent to the hardware and software deployed and accessible on the network. Sensitive data is thus no longer safe.

## How does a Wifi network intrusion test work?
The different equipments used, connected to each other, and their configurations will be analyzed in order to map the networks. Those which could potentially be accessible from outside the building will be identified. Access points will also be identified and their SSIDs masked.

Until a few years ago, a WEP key was enough to secure a wireless access point. Now, it only takes a few minutes to break this type of key. The WPA and especially WPA2 protocols are more secure, but are not always sufficient. Dictionary and brute force attacks will be performed to break these keys. The Wifi networks will be listed and analyzed, as well as the technologies used to secure them. The weakest protocol will be selected as it will represent a potential risk for all other networks.

A wireless network intrusion test generally lasts between five and ten days depending on the perimeter to be checked. It can be performed in black box (the company's teams are not aware that a security test is in progress, the tests are performed from outside) or in grey box (the auditor has a classic user account on the network).

## What to do after the Wifi intrusion test ?
At the end of the test, a complete report is written, including a complete mapping of the Wifi networks. A summary of the security flaws detected is presented with their detailed characteristics.

Each detected vulnerability is also the subject of a detailed technical sheet. It is classified according to its importance. The operations to be performed to reproduce and correct the security problem are also detailed.

Recommendations are also provided in order to implement a longer term cybersecurity policy. Taking these recommendations into account and implementing the recommended security measures is then the responsibility of the company.

However, it is recommended to perform a Wifi network intrusion test on a regular basis. It will be possible to verify that new vulnerabilities have not appeared and that the equipment, hardware and software, is always correctly configured and that the latest updates have been applied.

## Ressources 
- https://www.webtitan.com/blog/most-common-wireless-network-attacks/
- https://www.greycampus.com/opencampus/ethical-hacking/wi-fi-attacks#:~:text=Misconfiguration%20Attacks%3A,easily%20break%20into%20the%20network
- https://www.insecurity.fr/test-d-intrusion-wifi.html#_

## Pentesting steps
* Pre-engagement : This is surely the phase that many novices will neglect/forget, wrongly, because it is during this phase that we will define the scope of the test and the methods that will be used for it.

* Reconnaissance : Collecting as much publically accessible informations about the target as possible.

* Enumeration/Scanning : Discover the applications and services running on the systems, scan the ports (it's time for nmap).

* **Exploitation :** Exploit vulnerabilities discovered on a system or application either via public exploits or via exploitation of the application/system logic.

* Privilege Escalation : Once you have successfully exploited a system or application, a foothold in the jargon, you need to extend your access to the system. We talk about horizontal and vertical escalation, horizontal escalation corresponds to a transition to another user with the same permissions, vertical escalation corresponds to access to admin permissions.

* Post-exploitation : This phase is broken down into several sub-steps:

    - Full privilege collection : Additional information with a high-privileged user.

    - Pivoting : Check of other potential targets.

    - Clean-up : Erase the traces of your intrusion.

    - Reporting : Report harvesters, the flaws that have been discovered, the methods used, the paths, the tools, the commands, or any other relevant information that can be used in the last phase.

    - Remediation : Fixing and proposing solutions for all vulnerabilities that were identified during the reporting phase.


## Exercices
1. https://tryhackme.com/room/wifihacking101

### The basics - An Intro to WPA
Key Terms:
- SSID: The network "name" that you see when you try and connect
- ESSID: An SSID that *may* apply to multiple access points, eg a company office, normally forming a bigger network. For Aircrack they normally refer to the network you're attacking.
- BSSID: An access point MAC (hardware) address
- WPA2-PSK: Wifi networks that you connect to by providing a password that's the same for everyone
- WPA2-EAP: Wifi networks that you authenticate to by providing a username and password, which is sent to a RADIUS server.
- RADIUS: A server for authenticating clients, not just for wifi.

The core of WPA(2) authentication is the 4 way handshake.

Most home WiFi networks, and many others, use WPA(2) personal. If you have to log in with a password and it's not WEP, then it's WPA(2) personal. WPA2-EAP uses RADIUS servers to authenticate, so if you have to enter a username and password in order to connect then it's probably that.

Previously, the WEP (Wired Equivalent Privacy) standard was used. This was shown to be insecure and can be broken by capturing enough packets to guess the key via statistical methods.

The 4 way handshake allows the client and the AP to both prove that they know the key, without telling each other. WPA and WPA2 use practically the same authentication method, so the attacks on both are the same.

The keys for WPA are derived from both the ESSID and the password for the network. The ESSID acts as a salt, making dictionary attacks more difficult. It means that for a given password, the key will still vary for each access point. This means that unless you precompute the dictionary for just that access point/MAC address, you will need to try passwords until you find the correct one.

#### <b>Questions</b>

What type of attack on the encryption can you perform on WPA(2) personal?
> brute force

Can this method be used to attack WPA2-EAP handshakes? (Yea/Nay)
> nay

What three letter abbreviation is the technical term for the "wifi code/password/passphrase"?
> psk

What's the minimum length of a WPA2 Personal password?
> 8

### You're being watched - Capturing packets to attack

Using the Aircrack-ng suite, we can start attacking a wifi network. This will walk you through attacking a network yourself, assuming you have a monitor mode enabled NIC.

The aircrack-ng suite consists of:

    aircrack-ng
    airdecap-ng
    airmon-ng
    aireplay-ng
    airodump-ng
    airtun-ng
    packetforge-ng
    airbase-ng
    airdecloak-ng
    airolib-ng
    airserv-ng
    buddy-ng
    ivstools
    easside-ng
    tkiptun-ng
    wesside-ng

We'll want to use aircrack-ng, airodump-ng and airmon-ng to attack WPA networks.

The aircrack tools come by default with Kali, or can be installed with a package manager or from https://www.aircrack-ng.org/

I suggest creating a hotspot on a phone/tablet, picking a weak password (From rockyou.txt) and following along with every stage. To generate 5 random passwords from rockyou, you can use this command on Kali: `head /usr/share/wordlists/rockyou.txt -n 10000 | shuf -n 5 -`

You will need a monitor mode NIC in order to capture the 4 way handshake. Many wireless cards support this, but it's important to note that not all of them do.

Injection mode helps, as you can use it to deauth a client in order to force a reconnect which forces the handshake to occur again. Otherwise, you have to wait for a client to connect normally.

#### <b>Questions</b>

How do you put the interface “wlan0” into monitor mode with Aircrack tools? (Full command)
> airmon-ng wlan0 start

What is the new interface name likely to be after you enable monitor mode?
> wlan0mon

What do you do if other processes are currently trying to use that network adapter? 
> airmon-ng check kill

What tool from the aircrack-ng suite is used to create a capture?
> airodump-ng

What flag do you use to set the BSSID to monitor?
> --bssid

And to set the channel?
> --channel

And how do you tell it to capture packets to a file?
> -w

### Aircrack-ng - Let's Get Cracking
I will attach a capture for you to practice cracking on. If you are spending more than 3 mins cracking, something is likely wrong. (A single core VM on my laptop took around 1min).

In order to crack the password, we can either use aircrack itself or create a hashcat file in order to use GPU acceleration. There are two different versions of hashcat output file, most likely you want 3.6+ as that will work with recent versions of hashcat.

Useful Information:

BSSID: 02:1A:11:FF:D9:BD

ESSID: 'James Honor 8'

#### <b>Questions</b>

What flag do we use to specify a BSSID to attack?
> -b

What flag do we use to specify a wordlist?
> -w

How do we create a HCCAPX in order to use hashcat to crack the password?
> -j

Using the rockyou wordlist, crack the password in the attached capture. What's the password?
> greeneggsandham

Command:
> aircrack-ng -w /usr/share/wordlists/rockyou.txt files/NinjaJc01-01.cap

Where is password cracking likely to be fastest, CPU or GPU?
> GPU

## BeCode Exercice Writeup

During the first exercice it was pretty much the same as the TryHackMe room, we perform a deauth attack to capture the handshake.

We put the interface in monitor mode:
> sudo airmon-ng start wlan0

We dump the networks:
> sudo airodump-ng wlan0mon --bssid XX:XX:XX:XX:XX:XX

Generate some traffic:
> sudo aireplay-ng -a XX:XX:XX:XX:XX:XX --deauth 1 wlan0mon

Crack password with rockyou:
> aircrack-ng -w /usr/share/wordlists/rockyou.txt wpacrack-01.ivs

We get the password:
> hellokitty

The second exercice was a hashcat mask attack, the mask was ?u?d?l?l?u?l?s?s

See [this tutorial](https://www.4armed.com/blog/perform-mask-attack-hashcat/) to run a mask attack with hashcat.
