# DPC Latency Doctor

`latencydoctor.exe` is a Windows 11 x64 console utility for diagnosing and applying reversible low-latency tuning.

It does **not** patch Windows system files or binary drivers. That is intentionally avoided because Windows driver signing, PatchGuard, Secure Boot, and servicing can make that unsafe or unbootable. The tool instead collects evidence, creates backups, and applies reversible registry and power-policy changes.

## Build

From an MSYS2 MinGW64 shell:

```sh
make
```

Or from PowerShell, if `g++` is on `PATH`:

```powershell
g++ -std=gnu++17 -O2 -Wall -Wextra -municode -DUNICODE -D_UNICODE -o latencydoctor.exe latencydoctor.cpp -static -lpsapi -lversion -lsetupapi -lcfgmgr32 -lshlwapi -ladvapi32
```

## Use

Run a diagnostic scan:

```powershell
.\latencydoctor.exe scan 60
```

Preview optimizations:

```powershell
gsudo .\latencydoctor.exe optimize
```

Apply the safe optimization profile:

```powershell
gsudo .\latencydoctor.exe optimize --apply
```

For NVIDIA systems that show `nvlddmkm.sys`, `dxgkrnl.sys`, or `dxgmms2.sys` spikes, also try the reversible MPO workaround:

```powershell
gsudo .\latencydoctor.exe optimize --apply --disable-mpo
```

For timer tick problems, try this only after the normal profile:

```powershell
gsudo .\latencydoctor.exe optimize --apply --timer-tweaks
```

Collect a deep ETW trace:

```powershell
gsudo .\latencydoctor.exe trace 60
```

Open the generated `.etl` in Windows Performance Analyzer and inspect DPC/ISR Duration by module, function, and CPU.

## Restore

Each applied optimization creates a `latencydoctor-backup-YYYYMMDD-HHMMSS` folder with `.reg` exports and a change log. 
Restore imports the exports and also reads `changes.log` so values that were originally missing are removed again.

```powershell
gsudo .\latencydoctor.exe restore .\latencydoctor-backup-YYYYMMDD-HHMMSS
```

Reboot after applying or restoring.

## What the safe profile changes

- Multimedia scheduler latency keys:
  - `SystemResponsiveness = 0`
  - `NetworkThrottlingIndex = 0xffffffff`
- Power throttling:
  - `PowerThrottlingOff = 1`
- Current power scheme:
  - PCIe Link State Power Management off
  - USB selective suspend disabled
  - wireless adapter power saving set to maximum performance
- Network adapters:
  - disables common adapter power-saving knobs when the key already exists, such as Energy Efficient Ethernet, Green Ethernet, Auto Power Save, and Selective Suspend.

If `dxgkrnl.sys` and `dxgmms2.sys` have high DPC counts, `Wdf01000.sys` is often a framework messenger rather than the root cause.
Also, Gen Digital/AVG filter drivers are present and can add storage/network filter latency.

The normal profile targets power-management latency first. If `nvlddmkm.sys` remains high after reboot, test `--disable-mpo`, NVIDIA maximum performance mode, overlay removal, and a clean NVIDIA driver install or version rollback.
