/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       SCAN.C
*
*  VERSION:     1.10
*
*  DATE:        10 May 2017
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
    if (Entry->Next == NULL)
        return;

    Entry = Entry->Next;
    Entry->Next = NULL;

    Entry->Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (Entry->Name == NULL) {
        HeapFree(GetProcessHeap(), 0, Entry->Next);
        return;
    }

    _strncpy(Entry->Name, sz / sizeof(WCHAR), SymbolName, sz / sizeof(WCHAR));
    Entry->Address = lpAddress;
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
    WCHAR szFullSymbolInfo[MAX_PATH * 2];
    WCHAR szSymbolName[MAX_PATH];

    do {
        SymbolsFreeList();

        pSymSetOptions(
            SYMOPT_DEFERRED_LOADS |
            SYMOPT_UNDNAME |
            SYMOPT_OVERWRITE |
            SYMOPT_SECURE |
            SYMOPT_EXACT_SYMBOLS);

        RtlSecureZeroMemory(&g_SymbolsHead, sizeof(g_SymbolsHead));
        RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));
        if (GetModuleFileName(NULL, szSymbolName, MAX_PATH) == 0)
            break;

        _strcpy(szFullSymbolInfo, TEXT("SRV*"));
        _filepath(szSymbolName, _strend_w(szFullSymbolInfo));
        _strcat(szFullSymbolInfo, TEXT("Symbols"));
        if (!CreateDirectory(&szFullSymbolInfo[4], NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

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
* QueryKeInitAmd64SpecificStateOffsetSymbols
*
* Purpose:
*
* Search for KeInitAmd64SpecificState pattern address inside ntoskrnl.exe.
* Symbols version.
*
*/
BOOLEAN QueryKeInitAmd64SpecificStateOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *KeInitAmd64SpecificState
)
{
    ULONG_PTR Address = 0;
    PVOID Ptr;

    UNREFERENCED_PARAMETER(DllVirtualSize);

    switch (BuildNumber) {

    case 7601:
    case 9200:
    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:

        Address = (ULONG_PTR)SymbolAddressFromName(TEXT("KeInitAmd64SpecificState"));
        break;

    default:
        break;
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
* QueryExpLicenseWatchInitWorkerOffsetSymbols
*
* Purpose:
*
* Search for ExpLicenseWatchInitWorker pattern address inside ntoskrnl.exe.
* Symbols version.
*
*/
BOOLEAN QueryExpLicenseWatchInitWorkerOffsetSymbols(
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ExpLicenseWatchInitWorker
)
{
    ULONG_PTR Address = 0;
    PVOID Ptr;

    UNREFERENCED_PARAMETER(DllVirtualSize);

    switch (BuildNumber) {

    case 9200:
    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:

        Address = (ULONG_PTR)SymbolAddressFromName(TEXT("ExpLicenseWatchInitWorker"));
        break;

    default:
        break;
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
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *KiFilterFiberContext
)
{
    ULONG_PTR Address = 0;
    PVOID Ptr;

    UNREFERENCED_PARAMETER(DllVirtualSize);

    switch (BuildNumber) {

    case 7601:
    case 9200:
    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:

        Address = (ULONG_PTR)SymbolAddressFromName(TEXT("KiFilterFiberContext"));
        break;

    default:
        break;
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
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *CcInitializeBcbProfiler
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
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *SeValidateImageData
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
        // Required code located in PAGE section.
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
        SeValidateImageData->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Skip 'mov' instruction
        //
        SeValidateImageData->AddressOfPatch += (ULONG_PTR)SkipBytes;

        //
        // Assign patch data block to be written in patch routine.
        //
        SeValidateImageData->PatchData = pdSeValidateImageData;
        SeValidateImageData->SizeOfPatch = sizeof(pdSeValidateImageData);

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
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *SepInitializeCodeIntegrity
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
    _In_ ULONG BuildNumber,
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ImgpValidateImageHash
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
    _In_ PBYTE DllBase,
    _In_ SIZE_T DllVirtualSize,
    _In_ IMAGE_NT_HEADERS *NtHeaders,
    _Inout_ PATCH_CONTEXT *ImgpValidateImageHash
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
        ImgpValidateImageHash->AddressOfPatch = (ULONG_PTR)Ptr - (ULONG_PTR)DllBase;

        //
        // Assign patch data block to be written in patch routine.
        //
        ImgpValidateImageHash->PatchData = pdImgpValidateImageHash;
        ImgpValidateImageHash->SizeOfPatch = sizeof(pdImgpValidateImageHash);

    }
    return (Address != 0);
}
