# msf_udrl
POC udrl to replace metasploit's reflective loader with my own. It doesn't matter much because extensions (like stdapi) are also reflectively loaded with their own default. Useful to test a basic reverse shell/implant.

Mostly based off of KaynLdr

# Instructions
Just run `make` and use your loader of choice to run `Shellcode.x64.bin` in memory. The Makefile assumes a linux dev environment with `mingw` and `msfvenom` already installed. Change the listener interface (`LHOST`) and port (`LPORT`) as necessary.

# Credits
* [5pider](https://x.com/c5pider) for KaynLdr