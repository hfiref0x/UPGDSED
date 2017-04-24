/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       SCAN.C
*
*  VERSION:     1.00
*
*  DATE:        15 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

SYMBOL_ENTRY g_SymbolsHead;

pfnSymSetOptions        pSymSetOptions;
pfnSymInitializeW       pSymInitializeW = NULL;
pfnSymLoadModuleExW     pSymLoadModuleExW = NULL;
pfnSymEnumSymbolsW      pSymEnumSymbolsW = NULL;
pfnSymUnloadModule64    pSymUnloadModule64 = NULL;
pfnSymFromAddrW         pSymFromAddrW = NULL;
pfnSymCleanup           pSymCleanup = NULL;

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

        pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

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

        if (!pSymLoadModuleExW(hSym, NULL, lpFileName, NULL, ImageBase, 0, NULL, 0))
            break;

        if (!pSymEnumSymbolsW(hSym, ImageBase, NULL, SymEnumSymbolsProc, NULL))
            break;

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
