
# UPGDSED

## Universal PatchGuard and Driver Signature Enforcement Disable


# System Requirements

x64 Windows, supported versions:

* Windows 7 SP1
* Windows 8
* Windows 8.1
* Windows 10 (TH1/TH2/RS1/RS2/RS3)

Administrative privilege is required.

In case of EFI boot SecureBoot must be disabled.

# WARNING

Using this program might render your computer into an unbootable state.

Source code provided AS-IS in help it will be useful BUT WITHOUT WARRANTY OF ANY KIND.

ANY USE OF THE SOFTWARE IS ENTIRELY AT YOUR OWN RISK.

# Install

Run patch.exe elevated.


# Uninstall

In elevated command prompt type bcdedit /delete < patch guard disable entry id >

Navigate to Windows\System32 folder and delete ntkrnlmp.exe, osloader.exe (BIOS boot) or osloader.efi (EFI boot)


# Build 

UPGDSED comes with full source code.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

# References

* Bypassing PatchGuard on Windows x64 by Skywing, http://www.uninformed.org/?v=3&a=3&t=sumry
* Disable PatchGuard - the easy/lazy way by Fyyre, http://fyyre.ru/vault/bootloader.txt
* Disable PatchGuard  - updated for Win7 & Win8 by Fyyre, http://fyyre.ru/vault/bootloader_v2.txt
* bootkit_fasm - disables PG/DS via MBR bootkit by Fyyre, http://fyyre.ru/vault/bootkit_fasm.7z
* Kernel Patch Protection, https://en.wikipedia.org/wiki/Kernel_Patch_Protection
* Driver Signing Policy, https://msdn.microsoft.com/en-us/windows/hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-

# Authors
* EP_X0FF, https://github.com/hfiref0x
* Fyyre,   http://fyyre.ru

(c) 2017 - 2018 UPGDSED Project
