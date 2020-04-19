# Scripts #

This directory contains the following utility scripts:

### update_guids.ps1 ###

Pulls the latest GUID definitons from UEFITool's repository.

### protocols_db.py ###

Creates a JSON dictionary which maps a protocol GUID to the name(s) of the UEFI module(s) who installed it (e.g. by calling the `InstallProtocolInterface` boot service).

```json
  "86212936-0E76-41C8-A03A-2AF2FC1C39E2": [
    "C:\\Users\\carlsbad\\Code\\UEFI_RETool\\modules\\StatusCodeDxe"
  ],
  "D2B2B828-0826-48A7-B3DF-983C006024F0": [
    "C:\\Users\\carlsbad\\Code\\UEFI_RETool\\modules\\StatusCodeDxe"
  ],
  "BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7": [
    "C:\\Users\\carlsbad\\Code\\UEFI_RETool\\modules\\TcgPlatformSetupPolicy"
  ],
  "AFBFDE41-2E6E-4262-BA65-62B9236E5495": [
    "C:\\Users\\carlsbad\\Code\\UEFI_RETool\\modules\\TimestampDxe"
  ],
  "5859CB76-6BEF-468A-BE2D-B3DD1A27F012": [
    "C:\\Users\\carlsbad\\Code\\UEFI_RETool\\modules\\UHCD"
  ],
  ```

This can help in figuring out what dependencies must be satisfied in order to successfully load a DXE driver.
For example, suppose that during emulation we encounter the following output:

```
efi_emu> c
[DEBUG] Hit LocateProtocol() from 0x6e9c
[DEBUG] Request to LocateProtocol with GUID BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7 (Unknown GUID)
[DEBUG] Trying to locate protocol BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7
[DEBUG] Hit interrupt nr 3
[DEBUG] Backtrace 0x0
[+] Starting notification routines emulation...
[+] All done, main image emulation complete.
[DEBUG] [sync] TunnelSend: tunnel is unavailable
```

We can deduce that the module at hand tried to locate protocol with GUID BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7 and since this protocol wasn't found the code simply bailed out withut doing much.
However, based on the JSON file we can see that protocol BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7 gets registered by the `TcgPlatformSetupPolicy` module.
Knowing this, we can modify the `[protocols]` section in the `sample.ini` configuration file accordingly and re-run the emulation.
This time the dependency gets successfuly resolved we gain a much better code coverage:

```
[DEBUG] Hit LocateProtocol() from 0x6e9c
[DEBUG] Request to LocateProtocol with GUID BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7 (Unknown GUID)
[DEBUG] Trying to locate protocol BB6CBEFF-E072-40D2-A6EB-BAB75BDE87E7
[DEBUG] Found protocol!
[TAINT] Un-tainted memory range 0x203fff70-0x203fff78
[DEBUG] INSTRUCTION @ 0x0000000000006E9C: mov qword ptr [rsp + 0x60], rax
[TAINT] Tainting register rdx
[DEBUG] INSTRUCTION @ 0x0000000000006EB3: mov rdx, qword ptr [rsp + 0x98]
[DEBUG] Hit CopyMem() from 0x6ed7
[DEBUG] Asked to copy 0x1b bytes of mem from 0x40000001 to 0x203fff88
[TAINT] CopyMem() called with user-controllable parameters!
```
