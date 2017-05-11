/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       BCD.H
*
*  VERSION:     1.10
*
*  DATE:        11 May 2017
*
*  Common header file for the bcd support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define BCD_PATCH_ENTRY_GUID TEXT("{71A3C7FC-F751-4982-AEC1-E958357E6813}")

BOOL BcdPatchEntryAlreadyExist(
    _In_ LPWSTR EntryGuid,
    _Out_ PBOOL Result);

BOOL BcdCreatePatchEntry(
    _In_ ULONG BuildNumber);
