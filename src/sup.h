/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     1.00
*
*  DATE:        21 Apr 2017
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID supShowError(
    _In_ DWORD LastError,
    _In_ LPWSTR Msg);

_Success_(return == TRUE)
BOOL supGetBinaryBuildVersion(
    _In_ LPWSTR lpFileName,
    _Out_ ULONG *BuildNumber);

BOOL supEnablePrivilege(
    _In_ DWORD PrivilegeName,
    _In_ BOOL fEnable);

BOOLEAN supGetFirmwareType(
    _Out_ FIRMWARE_TYPE *FirmwareType);

BOOLEAN supSecureBootEnabled(
    _Out_ PBOOLEAN Enabled);

PVOID supLookupImageSectionByNameULONG(
    _In_ ULONG SectionName,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);

BOOLEAN supMakeCopyToTemp(
    _In_ BOOL IsEFI);

PVOID supMapFile(
    _In_ LPWSTR lpFileName,
    _Out_ PSIZE_T VirtualSize);

PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

BOOL supExtractSymDllsToTemp(
    VOID);

BOOL supPatchFile(
    _In_ LPWSTR lpFileName,
    _In_ ULONG_PTR *PatchContext,
    _In_ ULONG NumberOfPatches);

BOOL supRunProcessWithParamsAndWait(
    _In_ LPWSTR lpszParameters,
    _Out_ PDWORD ExitCode);

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
