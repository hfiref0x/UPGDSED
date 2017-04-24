/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        22 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "patterns.h"

fnptr_snwprintf_s _snwprintf_s;

HANDLE      g_ConOut = NULL;
HANDLE      g_ConIn = NULL;
BOOL        g_ConsoleOutput = FALSE;
BOOL        g_IsEFI = FALSE;
WCHAR       g_BE = 0xFEFF;

WCHAR       g_szTempDirectory[MAX_PATH + 1];
WCHAR       g_szSystemDirectory[MAX_PATH + 1];
WCHAR       g_szDeviceParition[MAX_PATH + 1];

//ntos

PATCH_CONTEXT CcInitializeBcbProfiler;
PATCH_CONTEXT SeValidateImageData;
PATCH_CONTEXT SepInitializeCodeIntegrity;

//winload
PATCH_CONTEXT ImgpValidateImageHash;

/*
* QuerySeValidateImageDataOffsetSymbols
*
* Purpose:
*
* Search for SeValidateImageData pattern address inside ntoskrnl.exe.
* Symbols version, 7601 signatures scan.
*
*/
BOOLEAN QuerySeValidateImageDataOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders
)
{
    ULONG ScanSize = 0, PatternSize = 0, SkipBytes = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, Pattern = NULL;
    PVOID ScanPtr = NULL;

    switch (BuildNumber) {

    case 7601:

        //
        // Windows 7 special case, SeValidateImageData pattern is not unique.
        // Requred code located in PAGE section.
        //

        ScanPtr = supLookupImageSectionByNameULONG('EGAP', DllBase, &ScanSize);
        if (ScanPtr) {
            Pattern = ptSeValidateImageData_7601;
            PatternSize = sizeof(ptSeValidateImageData_7601);
            SkipBytes = ptSkipBytesSeValidateImageData_7601;
        }
        break;

    case 9200:

        ScanPtr = DllBase;
        ScanSize = (ULONG)DllVirtualSize;
        Pattern = ptSeValidateImageData_9200;
        PatternSize = sizeof(ptSeValidateImageData_9200);
        SkipBytes = ptSkipBytesSeValidateImageData_9200;
        break;

    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:
    case 16170:

        ScanPtr = (PVOID)SymbolAddressFromName(TEXT("SeValidateImageData"));
        ScanSize = 0x200;
        Pattern = ptSeValidateImageData_9600_15063;
        PatternSize = sizeof(ptSeValidateImageData_9600_15063);
        SkipBytes = ptSkipBytesSeValidateImageData_9600_15063;
        break;

    default:
        break;
    }

    if ((ScanPtr == NULL) || (ScanSize == 0))
        return FALSE;

    if ((Pattern == NULL) || (PatternSize == 0))
        return FALSE;

    Address = (ULONG_PTR)FindPattern(
        ScanPtr,
        ScanSize,
        Pattern,
        PatternSize);

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        SeValidateImageData.AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Skip 'mov' instruction
        //
        SeValidateImageData.AddressOfPatch += SkipBytes;

        //
        // Assign patch data block to be written in patch routine.
        //
        SeValidateImageData.PatchData = pdSeValidateImageData;
        SeValidateImageData.SizeOfPatch = sizeof(pdSeValidateImageData);

    }

    return (Address != 0);
}

/*
* QueryCcInitializeBcbProfilerOffsetSymbols
*
* Purpose:
*
* Search for CcInitializeBcbProfiler pattern address inside ntoskrnl.exe.
* Symbols version, 7601 signatures scan.
*
*/
BOOLEAN QueryCcInitializeBcbProfilerOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders
)
{
    ULONG SectionSize;
    ULONG_PTR Address = 0;
    PVOID Ptr;
    PVOID SectionPtr;

    UNREFERENCED_PARAMETER(DllVirtualSize);

    switch (BuildNumber) {

    case 7601:
        //
        // Always in INIT section. Not in symbols, query address manually.
        //
        SectionPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &SectionSize);
        if (SectionPtr) {

            Address = (ULONG_PTR)FindPattern(
                SectionPtr,
                SectionSize,
                ptCcInitializeBcbProfiler_7601,
                sizeof(ptCcInitializeBcbProfiler_7601));

        }
        break;

    case 9200:
    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:

        Address = (ULONG_PTR)SymbolAddressFromName(TEXT("CcInitializeBcbProfiler"));
        break;

    default:
        break;
    }

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        CcInitializeBcbProfiler.AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        CcInitializeBcbProfiler.PatchData = pdCcInitializeBcbProfiler;
        CcInitializeBcbProfiler.SizeOfPatch = sizeof(pdCcInitializeBcbProfiler);

    }

    return (Address != 0);
}

/*
* QuerySepInitializeCodeIntegrityOffsetSymbols
*
* Purpose:
*
* Search for SepInitializeCodeIntegrity pattern address inside ntoskrnl.exe.
* Symbols version.
*
*/
BOOLEAN QuerySepInitializeCodeIntegrityOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders
)
{
    ULONG_PTR Address = 0;

    ULONG ScanSize, PatternSize = 0;
    PVOID ScanPtr, Pattern = NULL, Ptr;

    UNREFERENCED_PARAMETER(DllVirtualSize);

    ScanPtr = (PVOID)SymbolAddressFromName(TEXT("SepInitializeCodeIntegrity"));
    ScanSize = 0x200;

    switch (BuildNumber) {

    case 7601:
        Pattern = ptSepInitializeCodeIntegrity_7601;
        PatternSize = sizeof(ptSepInitializeCodeIntegrity_7601);
        break;

    case 9200:
    case 9600:
    case 10240:
    case 10586:
    case 14393:
        Pattern = ptSepInitializeCodeIntegrity_9200_14393;
        PatternSize = sizeof(ptSepInitializeCodeIntegrity_9200_14393);
        break;

    case 15063:
        Pattern = ptSepInitializeCodeIntegrity_15063;
        PatternSize = sizeof(ptSepInitializeCodeIntegrity_15063);
        break;

    default:
        break;
    }

    if ((Pattern == NULL) || (PatternSize == 0))
        return FALSE;

    Address = (ULONG_PTR)FindPattern(
        ScanPtr,
        ScanSize,
        Pattern,
        PatternSize);

    if (Address != 0) {
        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        SepInitializeCodeIntegrity.AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        SepInitializeCodeIntegrity.PatchData = pdSepInitializeCodeIntegrity;
        SepInitializeCodeIntegrity.SizeOfPatch = sizeof(pdSepInitializeCodeIntegrity);
    }

    return (Address != 0);
}

/*
* QueryImgpValidateImageHashOffsetSymbols
*
* Purpose:
*
* Search for ImgpValidateImageHash function address inside winload.exe/winload.efi.
* Symbols version.
*
*/
BOOLEAN QueryImgpValidateImageHashOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders
)
{
    ULONG_PTR Address = 0;
    PVOID Ptr;

    UNREFERENCED_PARAMETER(BuildNumber);
    UNREFERENCED_PARAMETER(DllVirtualSize);

    Address = (ULONG_PTR)SymbolAddressFromName(TEXT("ImgpValidateImageHash"));

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        ImgpValidateImageHash.AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ImgpValidateImageHash.PatchData = pdImgpValidateImageHash;
        ImgpValidateImageHash.SizeOfPatch = sizeof(pdImgpValidateImageHash);

    }
    return (Address != 0);
}

/*
* QueryImgpValidateImageHashOffsetSignatures
*
* Purpose:
*
* Search for ImgpValidateImageHash function address inside winload.exe/winload.efi.
* Signature pattern matching version.
*
*/
BOOLEAN QueryImgpValidateImageHashOffsetSignatures(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders
)
{
    ULONG_PTR Address = 0;
    ULONG PatternSize = 0;
    PVOID Pattern = NULL, Ptr;

    switch (BuildNumber) {

    case 7601:
        Pattern = ptImgpValidateImageHash_7601;
        PatternSize = sizeof(ptImgpValidateImageHash_7601);
        break;

    case 9200:
        Pattern = ptImgpValidateImageHash_9200;
        PatternSize = sizeof(ptImgpValidateImageHash_9200);
        break;

    case 9600:
        Pattern = ptImgpValidateImageHash_9600;
        PatternSize = sizeof(ptImgpValidateImageHash_9600);
        break;

    case 10240:
        Pattern = ptImgpValidateImageHash_10240;
        PatternSize = sizeof(ptImgpValidateImageHash_10240);
        break;

    case 10586:
        Pattern = ptImgpValidateImageHash_10586;
        PatternSize = sizeof(ptImgpValidateImageHash_10586);
        break;

    case 14393:
        Pattern = ptImgpValidateImageHash_14393;
        PatternSize = sizeof(ptImgpValidateImageHash_14393);
        break;

    case 15063:
        Pattern = ptImgpValidateImageHash_15063;
        PatternSize = sizeof(ptImgpValidateImageHash_15063);
        break;

    default:
        break;
    }

    if ((Pattern == NULL) || (PatternSize == 0))
        return FALSE;

    Address = (ULONG_PTR)FindPattern(
        DllBase,
        DllVirtualSize,
        Pattern,
        PatternSize);

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        ImgpValidateImageHash.AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ImgpValidateImageHash.PatchData = pdImgpValidateImageHash;
        ImgpValidateImageHash.SizeOfPatch = sizeof(pdImgpValidateImageHash);

    }
    return (Address != 0);
}

/*
* ScanNtos
*
* Purpose:
*
* Search for required patterns in ntoskrnl.exe.
*
*/
BOOLEAN ScanNtos()
{
    BOOLEAN             bCond = FALSE, bResult = FALSE;
    ULONG               BuildNumber = 0;

    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    IMAGE_NT_HEADERS   *NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];


    do {

        _strcpy(szBuffer, g_szTempDirectory);
        _strcat(szBuffer, NTOSKRNMP_EXE);

        if (!supGetBinaryBuildVersion(szBuffer, &BuildNumber)) {
            supShowError(ERROR_VERSION_PARSE_ERROR, TEXT("Cannot query ntoskrnl build number"));
            break;
        }

        //
        // Map ntos image.
        //
        DllBase = supMapFile(szBuffer, &DllVirtualSize);
        if (DllBase == NULL) {
            supShowError(GetLastError(), TEXT("Cannot map ntos file"));
            break;
        }

        NtHeaders = RtlImageNtHeader(DllBase);

        if (SymbolsLoadForFile(szBuffer, (DWORD64)DllBase)) {

            //
            // Scan for SeValidateImageData
            //
            if (!QuerySeValidateImageDataOffsetSymbols(BuildNumber, DllBase, DllVirtualSize, NtHeaders)) {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SeValidateImageData offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SeValidateImageData\t\t%08X"),
                SeValidateImageData.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            //
            // Scan for CcInitializeBcbProfiler
            //
            if (!QueryCcInitializeBcbProfilerOffsetSymbols(BuildNumber, DllBase, DllVirtualSize, NtHeaders)) {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query CcInitializeBcbProfiler offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> CcInitializeBcbProfiler\t%08X"),
                CcInitializeBcbProfiler.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            //
            //Scan for SepInitializeCodeIntegrity
            //
            if (!QuerySepInitializeCodeIntegrityOffsetSymbols(BuildNumber, DllBase, DllVirtualSize, NtHeaders)) {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SepInitializeCodeIntegrity offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SepInitializeCodeIntegrity\t%08X"),
                SepInitializeCodeIntegrity.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            SymbolsUnload((DWORD64)DllBase);
            bResult = TRUE;
        }
        else {
            supShowError(GetLastError(), TEXT("Cannot load symbols for the ntoslrnl"));
        }

    } while (bCond);

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    return bResult;
}

/*
* ScanWinload
*
* Purpose:
*
* Search for required patterns in winload.exe/winload.efi.
*
*/
BOOLEAN ScanWinload(
    VOID
)
{
    BOOLEAN             bCond = FALSE, bResult = FALSE;
    ULONG               BuildNumber = 0;

    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    IMAGE_NT_HEADERS   *NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];


    do {

        _strcpy(szBuffer, g_szTempDirectory);
        if (g_IsEFI != FALSE) {
            _strcat(szBuffer, OSLOAD_EFI);
        }
        else {
            _strcat(szBuffer, OSLOAD_EXE);
        }

        if (!supGetBinaryBuildVersion(szBuffer, &BuildNumber)) {
            supShowError(ERROR_VERSION_PARSE_ERROR, TEXT("Cannot query winload build number"));
            break;
        }

        //
        // Map winload image.
        //
        DllBase = supMapFile(szBuffer, &DllVirtualSize);
        if (DllBase == NULL) {
            supShowError(GetLastError(), TEXT("Cannot map winload file"));
            break;
        }

        NtHeaders = RtlImageNtHeader(DllBase);

        //
        // First attempt via symbols
        //
        if (SymbolsLoadForFile(szBuffer, (DWORD64)DllBase)) {

            if (QueryImgpValidateImageHashOffsetSymbols(BuildNumber, DllBase, DllVirtualSize, NtHeaders)) {
                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ImgpValidateImageHash\t%08X"),
                    ImgpValidateImageHash.AddressOfPatch);
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
                bResult = TRUE;
            }
            else {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query ImgpValidateImageHash offset using symbols"));
            }
            SymbolsUnload((DWORD64)DllBase);
        }
        else {
            supShowError(GetLastError(), TEXT("Cannot load symbols for the winload"));
        }

        //
        // If something wrong with symbols lookup try signatures scan.
        //
        if (bResult == FALSE) {
            cuiPrintText(g_ConOut, TEXT("Patch: Running signature scan for ImgpValidateImageHash"), g_ConsoleOutput, TRUE);
            bResult = QueryImgpValidateImageHashOffsetSignatures(BuildNumber, DllBase, DllVirtualSize, NtHeaders);
            if (!bResult)
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query ImgpValidateImageHash offset using signatures"));

        }

    } while (bCond);

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    return bResult;
}

/*
* ModifyFilesAndMove
*
* Purpose:
*
* Write changes to files and move them to system32 directory.
*
*/
BOOLEAN ModifyFilesAndMove(
    VOID
)
{
    SIZE_T DestLength;
    ULONG_PTR PatchContext[3];
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    _strcpy(szDest, g_szSystemDirectory);
    _strcat(szDest, TEXT("\\"));
    DestLength = _strlen(szDest);

    //
    // ntoskrnl
    //
    _strcpy(szBuffer, g_szTempDirectory);
    _strcat(szBuffer, NTOSKRNMP_EXE);
    _strcat(szDest, NTOSKRNMP_EXE);

    PatchContext[0] = (ULONG_PTR)&SeValidateImageData;
    PatchContext[1] = (ULONG_PTR)&CcInitializeBcbProfiler;
    PatchContext[2] = (ULONG_PTR)&SepInitializeCodeIntegrity;

    if (!supPatchFile(szBuffer, (ULONG_PTR*)&PatchContext, 3))
        return FALSE;

    if (!MoveFileEx(szBuffer,
        szDest,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        return FALSE;
    }

    //
    // winload
    //
    szDest[DestLength] = 0;
    _strcpy(szBuffer, g_szTempDirectory);
    if (g_IsEFI != FALSE) {
        _strcat(szDest, OSLOAD_EFI);
        _strcat(szBuffer, OSLOAD_EFI);
    }
    else {
        _strcat(szDest, OSLOAD_EXE);
        _strcat(szBuffer, OSLOAD_EXE);
    }

    PatchContext[0] = (ULONG_PTR)&ImgpValidateImageHash;

    if (!supPatchFile(szBuffer, (ULONG_PTR*)&PatchContext, 1))
        return FALSE;

    if (!MoveFileEx(szBuffer,
        szDest,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        return FALSE;
    }

    return TRUE;
}

/*
* DisablePeAuthAutoStart
*
* Purpose:
*
* Change PEAUTH service startup type from Auto to OnDemand.
*
*/
BOOL DisablePeAuthAutoStart(
    VOID
)
{
    BOOL bResult = FALSE;
    DWORD lastError = 0;
    SC_HANDLE Manager;
    SC_HANDLE Service;

    Manager = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS);

    if (Manager) {

        Service = OpenService(
            Manager,
            TEXT("PEAUTH"),
            SERVICE_CHANGE_CONFIG);
        if (Service) {

            bResult = ChangeServiceConfig(
                Service,
                SERVICE_NO_CHANGE,
                SERVICE_DEMAND_START,
                SERVICE_NO_CHANGE,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);

            lastError = GetLastError();

            CloseServiceHandle(Service);
        }
        CloseServiceHandle(Manager);
    }

    SetLastError(lastError);
    return bResult;
}

#define BCD_ENTRY_GUID TEXT("{71A3C7FC-F751-4982-AEC1-E958357E6813}")

/*
* SetupBCDEntry
*
* Purpose:
*
* Create new BCD Entry and write settings to it.
*
*/
BOOLEAN SetupBCDEntry(
    _In_ ULONG BuildNumber
)
{
    BOOLEAN bCond = FALSE, bResult = FALSE;
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
        //
        _strcat(szCommand, TEXT("-set {bootmgr} nointegritychecks 1"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Create new entry.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-create "));
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
        _strcat(szCommand, TEXT(" nx OptIn"));
        cuiPrintText(g_ConOut, &szCommand[CmdLength], g_ConsoleOutput, TRUE);

        if (!supRunProcessWithParamsAndWait(szCommand, &ExitCode))
            break;

        if (ExitCode != 0)
            break;

        //
        // Set nointegritychecks.
        //
        szCommand[Length] = 0;
        _strcat(szCommand, TEXT("-set "));
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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
        _strcat(szCommand, BCD_ENTRY_GUID);
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

        if (!DisablePeAuthAutoStart()) {
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

/*
* PatchMain
*
* Purpose:
*
* Program Main routine.
*
*/
UINT PatchMain()
{
    BOOLEAN bCond = FALSE;
    BOOLEAN bEnabled = FALSE;
    DWORD l = 0;
    FIRMWARE_TYPE FirmwareType;
    OSVERSIONINFO osver;
    INPUT_RECORD inp1;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    WCHAR szBuffer[MAX_PATH * 2];

    osver.dwOSVersionInfoSize = sizeof(osver);
    RtlGetVersion(&osver);

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut == INVALID_HANDLE_VALUE)
        return (UINT)-1;

    g_ConIn = GetStdHandle(STD_INPUT_HANDLE);
    if (g_ConIn == INVALID_HANDLE_VALUE)
        return (UINT)-2;

    g_ConsoleOutput = TRUE;
    if (!GetConsoleMode(g_ConOut, &l)) {
        g_ConsoleOutput = FALSE;
    }

    do {

        SetConsoleTitle(PROGRAMTITLE);
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &l, NULL);
        }

        cuiClrScr(g_ConOut);
        cuiPrintText(g_ConOut, PROGRAMFULLNAME, g_ConsoleOutput, TRUE);

        //
        // Warn user.
        //
        csbi.wAttributes = 0;
        GetConsoleScreenBufferInfo(g_ConOut, &csbi);
        SetConsoleTextAttribute(g_ConOut, FOREGROUND_RED | BACKGROUND_INTENSITY);
        _strcpy(szBuffer, TEXT("\n\rWARNING: Using this tool might render your PC to an unbootable state.\r\n"));
        _strcat(szBuffer, TEXT("If you want to continue type CONTINUE (all uppercase) and press Enter\r\n"));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
        SetConsoleTextAttribute(g_ConOut, csbi.wAttributes);

        l = 0;
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ReadConsole(g_ConIn, &szBuffer, MAX_PATH, &l, NULL);
        if (_strncmp(szBuffer, CONTINUE_CMD, _strlen(CONTINUE_CMD)) != 0)
            break;

        //
        // Query boot state
        //
        FirmwareType = FirmwareTypeUnknown;
        if (!supGetFirmwareType(&FirmwareType)) {
            supShowError(GetLastError(), TEXT("Cannot query firmware type."));
            break;
        }
        if ((FirmwareType != FirmwareTypeBios) &&
            (FirmwareType != FirmwareTypeUefi))
        {
            supShowError(ERROR_UNSUPPORTED_TYPE, TEXT("Unsupported firmware type."));
            break;
        }
        g_IsEFI = (FirmwareType == FirmwareTypeUefi);
        if (g_IsEFI) {
            //
            // Retrieve SecureBoot state.
            //          
            if (supSecureBootEnabled(&bEnabled)) {
                if (bEnabled != FALSE) {

                    supShowError(ERROR_UNSUPPORTED_TYPE,
                        TEXT("SecureBoot enabled. Disable it before using this program."));

                    break;
                }
            }
        }

        //
        // Output current Windoze version
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _snwprintf_s(szBuffer, MAX_PATH, MAX_PATH, L"Patch: Windows Version: %lu.%lu.%lu, %ws\n",
            osver.dwMajorVersion,
            osver.dwMinorVersion,
            osver.dwBuildNumber,
            (g_IsEFI != FALSE) ? TEXT("EFI") : TEXT("LegacyBIOS"));

        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        //
        // Check unsupported version.
        //
        if ((osver.dwBuildNumber < MIN_SUPPORTED_NT_BUILD) ||
            (osver.dwBuildNumber > MAX_SUPPORTED_NT_BUILD))
        {
            cuiPrintText(g_ConOut, TEXT("Patch: Unsupported Windows version"), g_ConsoleOutput, TRUE);
            break;
        }

        //
        // Get %TEMP% folder.
        //
        RtlSecureZeroMemory(&g_szTempDirectory, sizeof(g_szTempDirectory));
        if (ExpandEnvironmentStrings(TEXT("%temp%\\"), g_szTempDirectory, MAX_PATH) == 0) {
            supShowError(GetLastError(), TEXT("Cannot expand %TEMP% variable."));
            break;
        }

        //
        // Get device partition.
        //
        RtlSecureZeroMemory(&g_szDeviceParition, sizeof(g_szDeviceParition));
        if (ExpandEnvironmentStrings(TEXT("%SYSTEMDRIVE%"), g_szDeviceParition, MAX_PATH) == 0) {
            supShowError(GetLastError(), TEXT("Cannot expand %SYSTEMDRIVE% variable."));
            break;
        }

        //
        // Get System32 directory
        //
        RtlSecureZeroMemory(&g_szSystemDirectory, sizeof(g_szSystemDirectory));
        GetSystemDirectory(g_szSystemDirectory, MAX_PATH);

        //
        // Check BCDEDIT
        //
        _snwprintf_s(szBuffer,
            MAX_PATH,
            MAX_PATH,
            TEXT("%s\\%s"),
            g_szSystemDirectory,
            BCDEDIT_EXE);

        if (!PathFileExists(szBuffer)) {
            cuiPrintText(g_ConOut, TEXT("Patch: Error, bcdedit.exe not found."), g_ConsoleOutput, TRUE);
            break;
        }

        //
        // Extract DbgHelp and SymSrv to %TEMP%
        //
        if (!supExtractSymDllsToTemp()) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot extract symbol dlls to the %TEMP% folder."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Patch: Symbol dlls extracted successfully."), g_ConsoleOutput, TRUE);
        }

        //
        // Load DbgHelp and SymSrv and init all required pointers.
        //
        if (!InitDbgHelp()) {
            supShowError(ERROR_OPERATION_ABORTED, TEXT("Cannot initialize dbghelp."));
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Patch: Dbghelp initialized."), g_ConsoleOutput, TRUE);
        }

        //
        // Copy ntoskrnl & winload to %TEMP% as preparation for patch.
        //
        cuiPrintText(g_ConOut, TEXT("Patch: Copy files to %TEMP%"), g_ConsoleOutput, TRUE);
        if (!supMakeCopyToTemp(g_IsEFI)) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot copy files to the %TEMP% folder."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Patch: Copy success"), g_ConsoleOutput, TRUE);
        }

        //
        // Scan ntoskrnl for patch patterns.
        //
        cuiPrintText(g_ConOut, TEXT("Patch: Scanning ntoskrnl for patterns\n"), g_ConsoleOutput, TRUE);
        if (!ScanNtos()) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot locate patch offsets for ntoskrnl."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: Ntoskrnl scan complete"), g_ConsoleOutput, TRUE);
        }

        //
        // Scan winload for patch patterns.
        //
        cuiPrintText(g_ConOut, TEXT("Patch: Scanning winload for patterns\n"), g_ConsoleOutput, TRUE);
        if (!ScanWinload()) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot locate patch offsets for winload."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: Winload scan complete"), g_ConsoleOutput, TRUE);
        }

        //
        // Modify files and move them to %systemroot%\system32.
        //
        if (!ModifyFilesAndMove()) {
            supShowError(GetLastError(), TEXT("\nModifyFilesAndMove failed"));
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: ModifyFilesAndMove succeed"), g_ConsoleOutput, TRUE);
        }

        //
        // Setup new BCD entry.
        //
        if (!SetupBCDEntry(osver.dwBuildNumber)) {
            supShowError(GetLastError(), TEXT("\nSetupBCDEntry failed"));
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: SetupBCDEntry succeed"), g_ConsoleOutput, TRUE);
        }

    } while (bCond);

    cuiPrintText(g_ConOut, TEXT("Patch: Press any key to exit"), g_ConsoleOutput, TRUE);

    RtlSecureZeroMemory(&inp1, sizeof(inp1));
    ReadConsoleInput(g_ConIn, &inp1, 1, &l);
    ReadConsole(g_ConIn, &szBuffer, sizeof(g_BE), &l, NULL);

    cuiPrintText(g_ConOut, TEXT("Patch: Exit"), g_ConsoleOutput, TRUE);

    return 0;
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    HMODULE hNtdll;
    UINT err = 0;

    __security_init_cookie();

    hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        _snwprintf_s = (fnptr_snwprintf_s)GetProcAddress(hNtdll, "_snwprintf_s");
        if (_snwprintf_s) {
            err = PatchMain();
        }
    }

    ExitProcess(err);
}
