# Pdata Tampering
There are three programs in this repository:
* pdata - Small POC tampering with pdata section to mess with stack walkers. Intended to be ran by a debugger, since it triggers a DebugBreak in `VirtualAlloc`
* StackTrace - Uses `StackWalkEx` to check the call stack of `pdata.exe`
* msf_udrl - A reflective loader which implements module stomping with pdata tampering for the initial load of meterpreter.

# Credits
* [waldo](https://twitter.com/waldoirc) for the idea of tampering with the exception table
* [5pider](https://x.com/c5pider) for KaynLdr
