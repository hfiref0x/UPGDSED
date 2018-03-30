/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       SCAN.C
*
*  VERSION:     1.21
*
*  DATE:        29 Mar 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "patterns.h"

SYMBOL_ENTRY g_SymbolsHead;

pfnSymSetOptions        pSymSetOptions;
pfnSymInitializeW       pSymInitializeW = NULL;
pfnSymLoadModuleExW     pSymLoadModuleExW = NULL;
pfnSymEnumSymbolsW      pSymEnumSymbolsW = NULL;
pfnSymUnloadModule64    pSymUnloadModule64 = NULL;
pfnSymFromAddrW         pSymFromAddrW = NULL;
pfnSymCleanup           pSymCleanup = NULL;
pfnSymGetSymbolFileW     pSymGetSymbolFileW = NULL;

/*
* InitDbgHelp
*
* Purpose:
*
* This function loads dbghelp.dll, symsrv.dll from symdll directory and
* initialize function pointers from dbghelp.dll.
*
*/
BOOL InitDbgHelp(
    VOID
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hDbgHelp = NULL;
    SIZE_T Length;
    WCHAR szBuffer[MAX_PATH * 2];

    do {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        _strcpy(szBuffer, g_szTempDirectory);
        Length = _strlen(szBuffer);
        _strcat(szBuffer, TEXT("dbghelp.dll"));

        hDbgHelp = LoadLibrary(szBuffer);
        if (hDbgHelp == NULL)
            break;

        szBuffer[Length] = 0;
        _strcat(szBuffer, TEXT("symsrv.dll"));
        if (LoadLibrary(szBuffer)) {

            pSymSetOptions = (pfnSymSetOptions)GetProcAddress(hDbgHelp, "SymSetOptions");
            if (pSymSetOptions == NULL)
                break;

            pSymInitializeW = (pfnSymInitializeW)GetProcAddress(hDbgHelp, "SymInitializeW");
            if (pSymInitializeW == NULL)
                break;

            pSymLoadModuleExW = (pfnSymLoadModuleExW)GetProcAddress(hDbgHelp, "SymLoadModuleExW");
            if (pSymLoadModuleExW == NULL)
                break;

            pSymEnumSymbolsW = (pfnSymEnumSymbolsW)GetProcAddress(hDbgHelp, "SymEnumSymbolsW");
            if (pSymEnumSymbolsW == NULL)
                break;

            pSymUnloadModule64 = (pfnSymUnloadModule64)GetProcAddress(hDbgHelp, "SymUnloadModule64");
            if (pSymUnloadModule64 == NULL)
                break;

            pSymFromAddrW = (pfnSymFromAddrW)GetProcAddress(hDbgHelp, "SymFromAddrW");
            if (pSymFromAddrW == NULL)
                break;

            pSymCleanup = (pfnSymCleanup)GetProcAddress(hDbgHelp, "SymCleanup");
            if (pSymCleanup == NULL)
                break;

            pSymGetSymbolFileW = (pfnSymGetSymbolFileW)GetProcAddress(hDbgHelp, "SymGetSymbolFileW");
            if (pSymGetSymbolFileW == NULL)
                break;

            bResult = TRUE;
        }

    } while (bCond);

    return bResult;
}

/*
* SymbolsAddToList
*
* Purpose:
*
* This function add symbol to the list.
*
*/
VOID SymbolAddToList(
    LPWSTR SymbolName,
    DWORD64 lpAddress
)
{
    PSYMBOL_ENTRY Entry;
    SIZE_T        sz;

    Entry = &g_SymbolsHead;

    while (Entry->Next != NULL)
        Entry = Entry->Next;

    sz = (1 + _strlen(SymbolName)) * sizeof(WCHAR);

    Entry->Next = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYMBOL_ENTRY));
    if (Entry->Next) {

        Entry = Entry->Next;
        Entry->Next = NULL;

        Entry->Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (Entry->Name) {

            _strncpy(Entry->Name, sz / sizeof(WCHAR),
                SymbolName, sz / sizeof(WCHAR));

            Entry->Address = lpAddress;
        }
        else {
            HeapFree(GetProcessHeap(), 0, Entry);
        }
    }
}

/*
* SymbolAddressFromName
*
* Purpose:
*
* This function query address from the given symbol name.
*
*/
DWORD64 SymbolAddressFromName(
    _In_ LPWSTR lpszName
)
{
    PSYMBOL_ENTRY Entry;

    Entry = g_SymbolsHead.Next;

    while (Entry) {
        if (!_strcmp(lpszName, Entry->Name))
            return Entry->Address;
        Entry = Entry->Next;
    }
    return 0;
}

/*
* SymbolsFreeList
*
* Purpose:
*
* This function disposes symbols list.
*
*/
VOID SymbolsFreeList(
    VOID
)
{
    PSYMBOL_ENTRY Entry, Previous;

    Entry = g_SymbolsHead.Next;

    while (Entry) {
        Previous = Entry;
        Entry = Entry->Next;
        HeapFree(GetProcessHeap(), 0, Previous);
    }

    g_SymbolsHead.Next = NULL;
}

/*
* SymEnumSymbolsProc
*
* Purpose:
*
* Callback of SymEnumSymbolsW.
*
*/
BOOL CALLBACK SymEnumSymbolsProc(
    _In_ PSYMBOL_INFOW pSymInfo,
    _In_ ULONG SymbolSize,
    _In_opt_ PVOID UserContext
)
{
    UNREFERENCED_PARAMETER(SymbolSize);
    UNREFERENCED_PARAMETER(UserContext);

    SymbolAddToList(pSymInfo->Name, pSymInfo->Address);
    return TRUE;
}

/*
* SymbolsLoadForFile
*
* Purpose:
*
* Download symbols and dump them to the internal list.
*
*/
BOOL SymbolsLoadForFile(
    _In_ LPWSTR lpFileName,
    _In_ DWORD64 ImageBase
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hSym = GetCurrentProcess();
    WCHAR szFullSymbolInfo[MAX_PATH * 3];
    WCHAR szSymbolName[MAX_PATH];
    WCHAR szSymbolsDirectory[MAX_PATH * 2];

    do {
        SymbolsFreeList();

        pSymSetOptions(
            SYMOPT_DEFERRED_LOADS |
            SYMOPT_UNDNAME |
            SYMOPT_OVERWRITE |
            SYMOPT_SECURE |
            SYMOPT_EXACT_SYMBOLS);

        RtlSecureZeroMemory(&g_SymbolsHead, sizeof(g_SymbolsHead));

        //
        // Create symbols store subdirectory in the %temp% directory.
        //
        RtlSecureZeroMemory(&szSymbolsDirectory, sizeof(szSymbolsDirectory));
        _strcpy(szSymbolsDirectory, g_szTempDirectory);
        _strcat(szSymbolsDirectory, TEXT("Symbols"));
        if (!CreateDirectory(szSymbolsDirectory, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        _strcpy(szFullSymbolInfo, TEXT("SRV*"));
        _strcat(szFullSymbolInfo, szSymbolsDirectory);

        _strcat(szFullSymbolInfo, TEXT("*https://msdl.microsoft.com/download/symbols"));
        if (!pSymInitializeW(hSym, szFullSymbolInfo, FALSE))
            break;

        RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));

        if (pSymGetSymbolFileW(
            hSym, NULL,
            lpFileName, sfPdb,
            szSymbolName, MAX_PATH,
            szSymbolName, MAX_PATH))
        {
            if (!pSymLoadModuleExW(hSym, NULL, lpFileName, NULL, ImageBase, 0, NULL, 0))
                break;

            if (!pSymEnumSymbolsW(hSym, ImageBase, NULL, SymEnumSymbolsProc, NULL))
                break;
        }

        bResult = TRUE;

    } while (bCond);

    return bResult;
}

/*
* SymbolsUnload
*
* Purpose:
*
* Unload symbols and free resources.
*
*/
VOID SymbolsUnload(
    _In_ DWORD64 DllBase
)
{
    pSymUnloadModule64(NtCurrentProcess(), DllBase);
    pSymCleanup(NtCurrentProcess());
}

/*
* FindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID FindPattern(
    CONST PBYTE Buffer,
    SIZE_T BufferSize,
    CONST PBYTE Pattern,
    SIZE_T PatternSize
)
{
    PBYTE	p = Buffer;

    if (PatternSize == 0)
        return NULL;
    if (BufferSize < PatternSize)
        return NULL;
    BufferSize -= PatternSize;

    do {
        p = memchr(p, Pattern[0], BufferSize - (p - Buffer));
        if (p == NULL)
            break;

        if (memcmp(p, Pattern, PatternSize) == 0)
            return p;

        p++;
    } while (BufferSize - (p - Buffer) > 0); //-V555

    return NULL;
}

//
// PG part
//

/*
* QueryKeInitAmd64SpecificStateOffset
*
* Purpose:
*
* Search for KeInitAmd64SpecificState pattern address inside ntoskrnl.exe.
*
*/
BOOLEAN QueryKeInitAmd64SpecificStateOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *KeInitAmd64SpecificState
)
{
    ULONG ScanSize = 0, PatternSize = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, ScanPtr = NULL, Pattern = NULL;

    UNREFERENCED_PARAMETER(DllVirtualSize);
    UNREFERENCED_PARAMETER(Revision);

    Address = (ULONG_PTR)SymbolAddressFromName(TEXT("KeInitAmd64SpecificState"));
    if (Address == 0) {
        //
        // Symbols failed, switch to signatures.
        // Locate INIT section first.
        //
        ScanPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &ScanSize);
        if (ScanPtr) {

            switch (BuildNumber) {

            case 7601:
                Pattern = ptKeInitAmd64SpecificState_7601;
                PatternSize = sizeof(ptKeInitAmd64SpecificState_7601);
                break;

            case 9200:
            case 9600:
            case 10240:
            case 10586:
            case 14393:
            case 15063:
            case 16299:
                Pattern = ptKeInitAmd64SpecificState_9200_16299;
                PatternSize = sizeof(ptKeInitAmd64SpecificState_9200_16299);
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

        }
    }

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        KeInitAmd64SpecificState->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        KeInitAmd64SpecificState->PatchData = pdKeInitAmd64SpecificState;
        KeInitAmd64SpecificState->SizeOfPatch = sizeof(pdKeInitAmd64SpecificState);

    }

    return (Address != 0);
}

/*
* QueryExpLicenseWatchInitWorkerOffset
*
* Purpose:
*
* Search for ExpLicenseWatchInitWorker pattern address inside ntoskrnl.exe.
*
*/
BOOLEAN QueryExpLicenseWatchInitWorkerOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ExpLicenseWatchInitWorker
)
{
    ULONG ScanSize = 0, PatternSize = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, ScanPtr = NULL, Pattern = NULL;

    UNREFERENCED_PARAMETER(DllVirtualSize);
    UNREFERENCED_PARAMETER(Revision);

    Address = (ULONG_PTR)SymbolAddressFromName(TEXT("ExpLicenseWatchInitWorker"));
    if (Address == 0) {

        //
        // Symbols failed, switch to signatures.
        // Locate INIT section first.
        //
        ScanPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &ScanSize);
        if (ScanPtr) {

            switch (BuildNumber) {

            case 9200:
            case 15063:
                Pattern = ptExpLicenseWatchInitWorker1;
                PatternSize = sizeof(ptExpLicenseWatchInitWorker1);
                break;

            case 9600:
            case 10240:
            case 10586:
            case 14393:
            case 16299:
                Pattern = ptExpLicenseWatchInitWorker2;
                PatternSize = sizeof(ptExpLicenseWatchInitWorker2);
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

        }
    }

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        ExpLicenseWatchInitWorker->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ExpLicenseWatchInitWorker->PatchData = pdExpLicenseWatchInitWorker;
        ExpLicenseWatchInitWorker->SizeOfPatch = sizeof(pdExpLicenseWatchInitWorker);

    }

    return (Address != 0);
}

/*
* QueryKiFilterFiberContextOffset
*
* Purpose:
*
* Search for KiFilterFiberContext pattern address inside ntoskrnl.exe.
* Function main Patch Guard Initialization.
*
*/
BOOLEAN QueryKiFilterFiberContextOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *KiFilterFiberContext
)
{
    ULONG ScanSize = 0, PatternSize = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, ScanPtr = NULL, Pattern = NULL;

    UNREFERENCED_PARAMETER(DllVirtualSize);
    UNREFERENCED_PARAMETER(Revision);

    Address = (ULONG_PTR)SymbolAddressFromName(TEXT("KiFilterFiberContext"));
    if (Address == 0) {
        //
        // Symbols failed, switch to signatures.
        // Locate INIT section first.
        //
        ScanPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &ScanSize);
        if (ScanPtr) {

            switch (BuildNumber) {

            case 7601:
                Pattern = ptKiFilterFiberContext_7601;
                PatternSize = sizeof(ptKiFilterFiberContext_7601);
                break;

            case 9200:
                Pattern = ptKiFilterFiberContext_9200;
                PatternSize = sizeof(ptKiFilterFiberContext_9200);
                break;

            case 9600:
                Pattern = ptKiFilterFiberContext_9600;
                PatternSize = sizeof(ptKiFilterFiberContext_9600);
                break;

            case 10240:
            case 10586:
                Pattern = ptKiFilterFiberContext_10240_10586;
                PatternSize = sizeof(ptKiFilterFiberContext_10240_10586);
                break;

            case 14393:
            case 15063:
                Pattern = ptKiFilterFiberContext_14393_15063;
                PatternSize = sizeof(ptKiFilterFiberContext_14393_15063);
                break;

            case 16299:
                Pattern = ptKiFilterFiberContext_16299;
                PatternSize = sizeof(ptKiFilterFiberContext_16299);
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

        }
    }

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        KiFilterFiberContext->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        KiFilterFiberContext->PatchData = pdKiFilterFiberContext;
        KiFilterFiberContext->SizeOfPatch = sizeof(pdKiFilterFiberContext);

    }

    return (Address != 0);
}

/*
* QueryCcInitializeBcbProfilerOffset
*
* Purpose:
*
* Search for CcInitializeBcbProfiler pattern address inside ntoskrnl.exe.
*
*/
BOOLEAN QueryCcInitializeBcbProfilerOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *CcInitializeBcbProfiler
)
{
    BOOL bSymbolsFailed = FALSE;
    ULONG ScanSize = 0, PatternSize = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, ScanPtr = NULL, Pattern = NULL;

    UNREFERENCED_PARAMETER(DllVirtualSize);
    UNREFERENCED_PARAMETER(Revision);

    if (BuildNumber == 7601) {
        //
        // Always in INIT section. Not in symbols, query address manually.
        //
        ScanPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &ScanSize);
        if (ScanPtr) {

            Address = (ULONG_PTR)FindPattern(
                ScanPtr,
                ScanSize,
                ptCcInitializeBcbProfiler_7601,
                sizeof(ptCcInitializeBcbProfiler_7601));

        }

    }
    else {

        Address = (ULONG_PTR)SymbolAddressFromName(TEXT("CcInitializeBcbProfiler"));

        //
        // In case of symbols failure switch to signatures.
        //       
        if (Address == 0) {
            bSymbolsFailed = TRUE;
        }

    }

    //
    // In case if we cannot use symbols - query address by signature scan over INIT section.
    //
    if (bSymbolsFailed) {

        //
        // Always in INIT section.
        //
        ScanPtr = supLookupImageSectionByNameULONG('TINI', DllBase, &ScanSize);
        if (ScanPtr) {

            switch (BuildNumber) {

            case 9200:
                PatternSize = sizeof(ptCcInitializeBcbProfiler_9200);
                Pattern = ptCcInitializeBcbProfiler_9200;
                break;

            case 9600:
                PatternSize = sizeof(ptCcInitializeBcbProfiler_9600);
                Pattern = ptCcInitializeBcbProfiler_9600;
                break;

            case 10240:
            case 10586:
            case 14393:
            case 15063:
            case 16299:
                PatternSize = sizeof(ptCcInitializeBcbProfiler_10240_16299);
                Pattern = ptCcInitializeBcbProfiler_10240_16299;
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

        }
    }

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        CcInitializeBcbProfiler->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        CcInitializeBcbProfiler->PatchData = pdCcInitializeBcbProfiler;
        CcInitializeBcbProfiler->SizeOfPatch = sizeof(pdCcInitializeBcbProfiler);

    }

    return (Address != 0);
}

//
// DSE part
//

/*
* QuerySeValidateImageDataOffset
*
* Purpose:
*
* Search for SeValidateImageData pattern address inside ntoskrnl.exe.
* In case of symbols failure routine will use signatures scan.
*
*/
BOOLEAN QuerySeValidateImageDataOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *SeValidateImageData
)
{
    BOOL bSymbolsFailed = FALSE;
    ULONG ScanSize = 0, PatternSize = 0, PatchSize = 0, SkipBytes = 0;
    ULONG_PTR Address = 0;
    PVOID Ptr, Pattern = NULL, PatchData = NULL;
    PVOID ScanPtr = NULL;

    UNREFERENCED_PARAMETER(Revision);

    PatchData = pdSeValidateImageData;
    PatchSize = sizeof(pdSeValidateImageData);

    switch (BuildNumber) {

    case 7601:

        //
        // Windows 7 special case, SeValidateImageData pattern is not unique.
        // Required code located in PAGE section.
        //
        ScanPtr = supLookupImageSectionByNameULONG('EGAP', DllBase, &ScanSize);
        if (ScanPtr) {
            Pattern = ptSevalidateImageData_760X;
            PatternSize = sizeof(ptSevalidateImageData_760X);
            PatchData = pdSeValidateImageData_2;
            PatchSize = sizeof(pdSeValidateImageData_2);
            SkipBytes = 0;
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
    case 16299:

        Pattern = ptSeValidateImageData_9600_16299;
        PatternSize = sizeof(ptSeValidateImageData_9600_16299);

        ScanPtr = (PVOID)SymbolAddressFromName(TEXT("SeValidateImageData"));

        //
        // If symbols failed for some reason, set PAGE section as scan base.
        //
        if (ScanPtr == NULL) {
            ScanPtr = supLookupImageSectionByNameULONG('EGAP', DllBase, &ScanSize);
            bSymbolsFailed = TRUE;
        }
        else {
            ScanSize = 0x200;
        }

        SkipBytes = ptSkipBytesSeValidateImageData_9600_16299;
        break;

    default:
        break;
    }

    if ((ScanPtr == NULL) || (ScanSize == 0))
        return FALSE;

    //
    // Symbols failed for some reason, switch to signature scan.
    //
    if (bSymbolsFailed) {

        switch (BuildNumber) {

        case 9600:
        case 10240:
        case 10586:
        case 14393:
            Pattern = ptSeValidateImageData_2_9600_14393;
            PatternSize = sizeof(ptSeValidateImageData_2_9600_14393);
            break;

        case 15063:
        case 16299:
            Pattern = ptSeValidateImageData_2_15063_16299;
            PatternSize = sizeof(ptSeValidateImageData_2_15063_16299);
            break;

        default:
            break;

        }
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
        SeValidateImageData->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Apply "SkipBytes"
        //
        SeValidateImageData->AddressOfPatch += (ULONG_PTR)SkipBytes;

        //
        // Assign patch data block to be written in patch routine.
        //
        SeValidateImageData->PatchData = PatchData;
        SeValidateImageData->SizeOfPatch = PatchSize;

    }

    return (Address != 0);
}

/*
* QuerySepInitializeCodeIntegrityOffset
*
* Purpose:
*
* Search for SepInitializeCodeIntegrity pattern address inside ntoskrnl.exe.
*
*/
BOOLEAN QuerySepInitializeCodeIntegrityOffset(
    _In_ ULONG BuildNumber,
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *SepInitializeCodeIntegrity
)
{
    ULONG_PTR Address = 0;

    ULONG ScanSize, PatternSize = 0, SectionSize = 0;
    PVOID ScanPtr, Pattern = NULL, Ptr, SectionPtr = NULL;

    UNREFERENCED_PARAMETER(DllVirtualSize);
    UNREFERENCED_PARAMETER(Revision);

    //
    // Locate function pointer.
    //
    ScanPtr = (PVOID)SymbolAddressFromName(TEXT("SepInitializeCodeIntegrity"));
    if (ScanPtr == NULL) {
        //
        // Symbol unavailable, switch to signature scan.
        //
        SectionPtr = supLookupImageSectionByNameULONG('EGAP', DllBase, &SectionSize);
        if (SectionPtr) {

            switch (BuildNumber) {

            case 7601:
                Pattern = ptSepInitializeCodeIntegrity2_7601;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_7601);
                break;

            case 9200:
            case 9600:
                Pattern = ptSepInitializeCodeIntegrity2_9200_9600;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_9200_9600);
                break;

            case 10240:
            case 10586:
                Pattern = ptSepInitializeCodeIntegrity2_10240_10586;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_10240_10586);
                break;

            case 14393:
                Pattern = ptSepInitializeCodeIntegrity2_14393;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_14393);
                break;

            case 15063:
                Pattern = ptSepInitializeCodeIntegrity2_15063;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_15063);
                break;

            case 16299:
                Pattern = ptSepInitializeCodeIntegrity2_16299;
                PatternSize = sizeof(ptSepInitializeCodeIntegrity2_16299);
                break;

            default:
                break;
            }

            if ((Pattern == NULL) || (PatternSize == 0))
                return FALSE;

            ScanPtr = FindPattern(
                SectionPtr,
                SectionSize,
                Pattern,
                PatternSize);

        }

    }

    //
    // Scan for specific place inside found fuction.
    //
    ScanSize = 0x200;
    Pattern = NULL;
    PatternSize = 0;

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

    case 16299:
        Pattern = ptSepInitializeCodeIntegrity_16299;
        PatternSize = sizeof(ptSepInitializeCodeIntegrity_16299);
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
        SepInitializeCodeIntegrity->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        SepInitializeCodeIntegrity->PatchData = pdSepInitializeCodeIntegrity;
        SepInitializeCodeIntegrity->SizeOfPatch = sizeof(pdSepInitializeCodeIntegrity);
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
    _In_ PBYTE DllBase,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ImgpValidateImageHash
)
{
    ULONG_PTR Address = 0;
    PVOID Ptr;

    Address = (ULONG_PTR)SymbolAddressFromName(TEXT("ImgpValidateImageHash"));

    if (Address != 0) {

        //
        // Convert to physical offset in file.
        //
        Ptr = RtlAddressInSectionTable(NtHeaders, DllBase, (ULONG)(Address - (ULONG_PTR)DllBase));
        ImgpValidateImageHash->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ImgpValidateImageHash->PatchData = pdImgpValidateImageHash;
        ImgpValidateImageHash->SizeOfPatch = sizeof(pdImgpValidateImageHash);

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
    _In_ ULONG Revision,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ImgpValidateImageHash
)
{
    ULONG_PTR Address = 0;
    ULONG PatternSize = 0;
    PVOID Pattern = NULL, Ptr;

    UNREFERENCED_PARAMETER(Revision);

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

    case 16299:
        Pattern = ptImgpValidateImageHash_16299;
        PatternSize = sizeof(ptImgpValidateImageHash_16299);
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
        ImgpValidateImageHash->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ImgpValidateImageHash->PatchData = pdImgpValidateImageHash;
        ImgpValidateImageHash->SizeOfPatch = sizeof(pdImgpValidateImageHash);

    }
    return (Address != 0);
}
