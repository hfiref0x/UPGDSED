/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       BCD.C
*
*  VERSION:     1.11
*
*  DATE:        28 June 2017
*
*  Boot Configuration Data related routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* BcdRtlStrToUl
*
* Purpose:
*
* wcstoul simplified.
*
*/
unsigned long BcdRtlStrToUl(wchar_t *s)
{
    unsigned long long	a = 0;
    wchar_t			c;

    if (s == 0)
        return 0;

    while (*s != 0) {
        c = *s;
        if (_isdigit_w(c))
            a = (a * 10) + (c - L'0');
        else
            break;

        if (a > ULONG_MAX)
            return ULONG_MAX;

        s++;
    }
    return (unsigned long)a;
}

/*
* BcdOpenKey
*
* Purpose:
*
* Open store key.
*
*/
NTSTATUS BcdOpenKey(
    _In_opt_ HANDLE hRootKey,
    _In_ LPWSTR KeyName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ HANDLE *hKey
)
{
    OBJECT_ATTRIBUTES Obja;
    UNICODE_STRING usName;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    usName.Buffer = NULL;
    usName.Length = 0;
    usName.MaximumLength = 0;
    RtlInitUnicodeString(&usName, KeyName);
    InitializeObjectAttributes(&Obja, &usName, OBJ_CASE_INSENSITIVE, hRootKey, NULL);
    Status = NtOpenKey(hKey, DesiredAccess, &Obja);
    return Status;
}

/*
* BcdReadValue
*
* Purpose:
*
* Read given value to output buffer.
* Returned Buffer must be released with RtlFreeHeap after use.
*
*/
NTSTATUS BcdReadValue(
    _In_ HANDLE hKey,
    _In_ LPWSTR ValueName,
    _Out_ PVOID *Buffer,
    _Out_ ULONG *BufferSize
)
{
    KEY_VALUE_PARTIAL_INFORMATION *kvpi;
    UNICODE_STRING usName;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Length = 0;
    PVOID CopyBuffer = NULL;

    *Buffer = NULL;
    *BufferSize = 0;

    usName.Buffer = NULL;
    usName.Length = 0;
    usName.MaximumLength = 0;

    RtlInitUnicodeString(&usName, ValueName);
    Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL) {

        kvpi = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length);
        if (kvpi) {

            Status = NtQueryValueKey(hKey, &usName, KeyValuePartialInformation, kvpi, Length, &Length);
            if (NT_SUCCESS(Status)) {

                CopyBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, kvpi->DataLength);
                if (CopyBuffer) {
                    RtlCopyMemory(CopyBuffer, kvpi->Data, kvpi->DataLength);
                    *Buffer = CopyBuffer;
                    *BufferSize = kvpi->DataLength;
                    Status = STATUS_SUCCESS;
                }
                else
                {
                    Status = STATUS_NO_MEMORY;
                }

            }
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, kvpi);
        }
        else {
            Status = STATUS_NO_MEMORY;
        }
    }

    return Status;
}

/*
* BcdIsSystemStoreCandidate
*
* Purpose:
*
* Check if store marked as "System".
*
*/
BOOLEAN BcdIsSystemStoreCandidate(
    _In_ HANDLE hKey
)
{
    BOOLEAN bResult = FALSE;
    PDWORD Value = NULL;
    ULONG Length = 0;
    NTSTATUS Status;

    Status = BcdReadValue(hKey, L"System", &Value, &Length);
    if (NT_SUCCESS(Status)) {

        if (Length == sizeof(DWORD)) {
            bResult = (*Value == 1);
        }

        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Value);
    }

    return bResult;
}

/*
* BcdIsSystemStore
*
* Purpose:
*
* Perform validation of given store to be System store type.
*
*/
NTSTATUS BcdIsSystemStore(
    _In_ HANDLE hRootKey,
    _In_ LPWSTR KeyName,
    _Out_ PBOOL Result
)
{
    ULONG Length = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hKey = NULL, hSubKey = NULL;
    PDWORD Value;

    if (Result)
        *Result = FALSE;

    hKey = NULL;
    Status = BcdOpenKey(hRootKey, KeyName, KEY_READ, &hKey);
    if (NT_SUCCESS(Status)) {

        hSubKey = NULL;
        Status = BcdOpenKey(hKey, L"Description", KEY_READ, &hSubKey);
        if (NT_SUCCESS(Status)) {

            //
            // Is this system store candidate?
            //
            if (BcdIsSystemStoreCandidate(hSubKey)) {
                Length = 0;
                Value = NULL;
                Status = BcdReadValue(hSubKey, L"TreatAsSystem", &Value, &Length);
                if (NT_SUCCESS(Status)) {

                    if (Length == sizeof(DWORD)) {
                        if (*Value == 1) {
                            *Result = TRUE;
                            Status = STATUS_SUCCESS;
                        }
                    }

                    RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Value);
                }
                else {
                    Status = STATUS_INVALID_VARIANT;
                }
            }
            NtClose(hSubKey);
        }
        NtClose(hKey);
    }
    return Status;
}

/*
* BcdFindEntryGuid
*
* Purpose:
*
* Enumerate subkeys for Objects root key and lookup given guid.
*
*/
BOOL BcdFindEntryGuid(
    _In_ HANDLE hRootKey,
    _In_ LPWSTR EntryGuid
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    NTSTATUS Status;
    ULONG Length = 0, cSubKeys, SubIndex = 0;
    SIZE_T Size;
    HANDLE hKey;

    KEY_FULL_INFORMATION ki;
    KEY_BASIC_INFORMATION *kbi;

    do {

        hKey = NULL;
        Status = BcdOpenKey(hRootKey, L"Objects", KEY_READ, &hKey);
        if (!NT_SUCCESS(Status))
            break;

        Status = NtQueryKey(
            hKey,
            KeyFullInformation,
            (PVOID)&ki,
            sizeof(KEY_FULL_INFORMATION),
            &Length);

        if ((Status != STATUS_SUCCESS) && (Status != STATUS_BUFFER_OVERFLOW))
            break;

        cSubKeys = ki.SubKeys;
        Size = sizeof(KEY_BASIC_INFORMATION) + ki.MaxNameLen + 2;

        kbi = RtlAllocateHeap(
            NtCurrentPeb()->ProcessHeap,
            0,
            Size);

        if (kbi) {

            do {
                RtlSecureZeroMemory(kbi, Size);
                Status = NtEnumerateKey(hKey, SubIndex, KeyBasicInformation, kbi, (ULONG)Size, &Length);

                if (Status == STATUS_NO_MORE_ENTRIES)
                    break;

                if (!NT_SUCCESS(Status))
                    break;

                if (kbi->NameLength > ki.MaxNameLen + 2)
                    break;

                if (_strcmpi(kbi->Name, EntryGuid) == 0) {
                    bResult = TRUE;
                    break;
                }

                SubIndex++;
                cSubKeys--;

            } while (cSubKeys);
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, kbi);
        }

    } while (bCond);

    if (hKey) NtClose(hKey);

    return bResult;
}

/*
* BcdPatchEntryAlreadyExist
*
* Purpose:
*
* Check if patch entry already created.
*
*/
BOOL BcdPatchEntryAlreadyExist(
    _In_ LPWSTR EntryGuid,
    _Out_ PBOOL Result
)
{
    BOOL IsSystemStore = FALSE, bCond = FALSE;
    BOOL bSuccess = FALSE;
    HANDLE hKey, hSubKey;
    ULONG SubIndex = 0, Length = 0, cSubKeys = 0, tmp;
    SIZE_T Size;
    NTSTATUS Status;

    KEY_FULL_INFORMATION ki;
    KEY_BASIC_INFORMATION *kbi;

    if (Result)
        *Result = FALSE;

    do {

        //
        // Open Machine root key.
        //

        hKey = NULL;
        Status = BcdOpenKey(NULL, L"\\Registry\\Machine", KEY_READ, &hKey);
        if (!NT_SUCCESS(Status))
            break;

        RtlSecureZeroMemory(&ki, sizeof(KEY_FULL_INFORMATION));

        //
        // Query number of top level keys.
        //
        Status = NtQueryKey(
            hKey,
            KeyFullInformation,
            (PVOID)&ki,
            sizeof(KEY_FULL_INFORMATION),
            &Length);

        if ((Status != STATUS_SUCCESS) && (Status != STATUS_BUFFER_OVERFLOW))
            break;

        if ((ki.MaxNameLen == 0) || (ki.SubKeys == 0))
            break;

        //
        // Allocate memory for keys enumeration.
        //
        cSubKeys = ki.SubKeys;
        Size = sizeof(KEY_BASIC_INFORMATION) + ki.MaxNameLen + 2;

        kbi = RtlAllocateHeap(
            NtCurrentPeb()->ProcessHeap,
            0,
            Size);

        if (kbi) {

            do {
                RtlSecureZeroMemory(kbi, Size);
                Status = NtEnumerateKey(hKey, SubIndex, KeyBasicInformation, kbi, (ULONG)Size, &Length);

                if (Status == STATUS_NO_MORE_ENTRIES)
                    break;

                if (!NT_SUCCESS(Status))
                    break;

                //
                // Buffer overflow.
                //
                if (kbi->NameLength > ki.MaxNameLen + 2)
                    break;

                //
                // Validate BCD key name.
                //
                // Name format:
                //               BCD + XXXXXXXXUL
                //
                if (_strncmpi_w(kbi->Name, L"BCD", 3) == 0) {
                    tmp = BcdRtlStrToUl(&kbi->Name[3]);
                    //
                    // Conversion error, wrong key.
                    //
                    if (tmp == ULONG_MAX) {
                        SubIndex++;
                        cSubKeys--;
                        continue;
                    }

                    //
                    // Check if this key is system store.
                    //
                    if (!NT_SUCCESS(BcdIsSystemStore(hKey, kbi->Name, &IsSystemStore))) {
                        SubIndex++;
                        cSubKeys--;
                        continue;
                    }

                    if (IsSystemStore) {

                        hSubKey = NULL;
                        Status = BcdOpenKey(hKey, kbi->Name, KEY_READ, &hSubKey);
                        if (NT_SUCCESS(Status)) {

                            *Result = BcdFindEntryGuid(hSubKey, EntryGuid);
                            bSuccess = TRUE;

                            NtClose(hSubKey);
                        }
                        break;
                    }

                }

                SubIndex++;
                cSubKeys--;

            } while (cSubKeys);

            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, kbi);
        }

    } while (bCond);

    if (hKey) NtClose(hKey);

    return bSuccess;
}

/*
* BcdCreatePatchEntry
*
* Purpose:
*
* Create new BCD Entry and write settings to it.
*
*/
BOOL BcdCreatePatchEntry(
    _In_ ULONG BuildNumber
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    DWORD ExitCode;
    SIZE_T Length, CmdLength;
    WCHAR szCommand[MAX_PATH * 3];

    RtlSecureZeroMemory(szCommand, sizeof(szCommand));

    _snwprintf_s(szCommand,
        MAX_PATH,
        MAX_PATH,
        TEXT("%ws\\%ws "),
        g_szSystemDirectory,
        BCDEDIT_EXE);

    Length = _strlen(szCommand);
    if (Length <= BCDEDIT_LENGTH)
        return FALSE;

    CmdLength = Length - BCDEDIT_LENGTH;

    cuiPrintText(g_ConOut, TEXT("Patch: Executing BCDEDIT commands"), g_ConsoleOutput, TRUE);

    do {

        //
        // Set bootmgr option
        // Commented for bitlocker compatibility.
        //
       /* _strcat(szCommand, TEXT("-set {bootmgr} nointegritychecks 1"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;*/

            //
            // Create new entry.
            //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-create "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" -d \"Patch Guard Disabled\" -application OSLOADER"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set device partition.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" device partition="));
        _strcat(szCommand, g_szDeviceParition);
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set osdevice partition.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" osdevice partition="));
        _strcat(szCommand, g_szDeviceParition);
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set systemroot.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" systemroot \\Windows"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set osloader path.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" path \\Windows\\system32\\"));

        if (g_IsEFI) {
            _strcat(szCommand, OSLOAD_EFI);
        }
        else {
            _strcat(szCommand, OSLOAD_EXE);
        }
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set kernel.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" kernel "));
        _strcat(szCommand, NTOSKRNMP_EXE);
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set recoveryenabled.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" recoveryenabled 0"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set Nx.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" nx OptIn"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set nointegritychecks for our GUID entry.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" nointegritychecks 1"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set inherit bootloader settings.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" inherit {bootloadersettings}"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set display order.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-displayorder "));
        _strcat(szCommand, BCD_PATCH_ENTRY_GUID);
        _strcat(szCommand, TEXT(" -addlast"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set timeout.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-timeout 10"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set bootmenupolicy to Legacy for everything above Windows 7 SP1
        //
        if (BuildNumber > 7601) {
            szCommand[Length] = 0;
            _strcat(szCommand, TEXT("-set bootmenupolicy legacy"));
            cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);
            if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
                break;

            if (ExitCode != 0)
                break;
        }

        //
        // Disable PEAUTH autostart.
        //
        cuiPrintText(g_ConOut,
            TEXT("Patch: Setting PeAuth service to manual start"),
            g_ConsoleOutput,
            TRUE);

        if (!supDisablePeAuthAutoStart()) {
            supShowError(GetLastError(),
                TEXT("Could not set PeAuth service to manual start"));
        }
        else {
            cuiPrintText(g_ConOut,
                TEXT("Patch: PeAuth service set to manual start"),
                g_ConsoleOutput,
                TRUE);
        }

        bResult = TRUE;

    } while (bCond);


    return bResult;
}
