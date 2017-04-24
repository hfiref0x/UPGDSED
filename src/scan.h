/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       SCAN.H
*
*  VERSION:     1.00
*
*  DATE:        15 Apr 2017
*
*  Header file for image scan routine prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

PVOID FindPattern(
    CONST PBYTE Buffer,
    SIZE_T BufferSize,
    CONST PBYTE Pattern,
    SIZE_T PatternSize);

BOOL InitDbgHelp(
    VOID);

BOOL SymbolsLoadForFile(
    _In_ LPWSTR lpFileName,
    _In_ DWORD64 ImageBase);

VOID SymbolsUnload(
    _In_ DWORD64 DllBase);

DWORD64 SymbolAddressFromName(
    _In_ LPWSTR lpszName);

typedef  DWORD(WINAPI *pfnSymSetOptions)(
    _In_ DWORD   SymOptions
    );

typedef BOOL(WINAPI *pfnSymInitializeW)(
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess);

typedef DWORD64(WINAPI *pfnSymLoadModuleExW)(
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_opt_ DWORD Flags);

typedef BOOL(WINAPI *pfnSymEnumSymbolsW)(
    _In_ HANDLE hProcess,
    _In_ ULONG64 BaseOfDll,
    _In_opt_ PCWSTR Mask,
    _In_ PSYM_ENUMERATESYMBOLS_CALLBACKW EnumSymbolsCallback,
    _In_opt_ PVOID UserContext);

typedef BOOL(WINAPI *pfnSymUnloadModule64)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 BaseOfDll);

typedef BOOL(WINAPI *pfnSymCleanup)(
    _In_ HANDLE hProcess);

typedef BOOL(WINAPI *pfnSymFromAddrW)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _Out_opt_ PDWORD64 Displacement,
    _Inout_ PSYMBOL_INFOW Symbol);
