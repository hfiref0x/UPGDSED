/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       SUP.C
*
*  VERSION:     1.20
*
*  DATE:        20 Oct 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supShowError
*
* Purpose:
*
* Display detailed last error to user.
*
*/
VOID supShowError(
    _In_ DWORD LastError,
    _In_ LPWSTR Msg
)
{
    LPWSTR lpMsgBuf = NULL;
    WCHAR szErrorMsg[MAX_PATH * 2];

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, LastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf, 0, NULL))
    {
        RtlSecureZeroMemory(&szErrorMsg, sizeof(szErrorMsg));
        _snwprintf_s(szErrorMsg, MAX_PATH * 2, MAX_PATH, TEXT("\n\rPatch: %ws: %ws"), Msg, lpMsgBuf);
        LocalFree(lpMsgBuf);
        cuiPrintText(g_ConOut, szErrorMsg, g_ConsoleOutput, TRUE);
    }
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
    _In_ DWORD	PrivilegeName,
    _In_ BOOL	fEnable
)
{
    BOOL             bResult = FALSE;
    NTSTATUS         status;
    HANDLE           hToken;
    TOKEN_PRIVILEGES TokenPrivileges;

    status = NtOpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken);

    if (!NT_SUCCESS(status)) {
        return bResult;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
    TokenPrivileges.Privileges[0].Luid.HighPart = 0;
    TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
    if (status == STATUS_NOT_ALL_ASSIGNED) {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    bResult = NT_SUCCESS(status);
    NtClose(hToken);
    return bResult;
}

/*
* supGetFirmwareType
*
* Purpose:
*
* Query current machine firmware type.
*
*/
BOOLEAN supGetFirmwareType(
    _Out_ FIRMWARE_TYPE *FirmwareType
)
{
    NTSTATUS Status;
    ULONG returnedLength = 0;
    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;

    RtlSecureZeroMemory(&sbei, sizeof(sbei));
    Status = NtQuerySystemInformation(
        SystemBootEnvironmentInformation,
        &sbei,
        sizeof(sbei),
        &returnedLength);

    if (FirmwareType)
        *FirmwareType = sbei.FirmwareType;

    SetLastError(RtlNtStatusToDosError(Status));

    return NT_SUCCESS(Status);
}

/*
* supSecureBootEnabled
*
* Purpose:
*
* Return FALSE on any error and TRUE on success query.
*
*/
BOOLEAN supSecureBootEnabled(
    _Out_ PBOOLEAN Enabled
)
{
    BOOLEAN SecureBootEnabled = FALSE;

    if (supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE)) {

        GetFirmwareEnvironmentVariable(L"SecureBoot",
            L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &SecureBootEnabled, sizeof(BOOLEAN));

        supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE);
    }

    *Enabled = SecureBootEnabled;
    return TRUE;
}

/*
* supGetBinaryVersionNumbers
*
* Purpose:
*
* Return version numbers from version info.
*
*/
_Success_(return == TRUE)
BOOL supGetBinaryVersionNumbers(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID *)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    if (MajorVersion)
                        *MajorVersion = HIWORD(pFileInfo->dwFileVersionMS);                   
                    if (MinorVersion)
                        *MinorVersion = LOWORD(pFileInfo->dwFileVersionMS);
                    if (Build)
                        *Build = HIWORD(pFileInfo->dwFileVersionLS);
                    if (Revision) 
                        *Revision = LOWORD(pFileInfo->dwFileVersionLS);
                }
            }
            HeapFree(GetProcessHeap(), 0, vinfo);
        }
    }
    return bResult;
}

/*
* supLookupImageSectionByNameULONG
*
* Purpose:
*
* Lookup section pointer and size for ulong size section name.
*
*/
PVOID supLookupImageSectionByNameULONG(
    _In_ ULONG SectionName,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS *NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER *SectionTableEntry;

    if (SectionSize)
        *SectionSize = 0;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {
        if (*(PULONG)SectionTableEntry->Name == SectionName)
            if (SectionTableEntry->Name[4] == 0) {
                bFound = TRUE;
                break;
            }
        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

/*
* supMakeCopyToTemp
*
* Purpose:
*
* Copy required files to %temp%.
*
*/
BOOLEAN supMakeCopyToTemp(
    _In_ BOOL IsEFI
)
{
    SIZE_T l, k;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    _strcpy(szSource, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szSource, L"\\system32\\");
    l = _strlen(szSource);
    _strcat(szSource, NTOSKRNL_EXE);

    _strcpy(szDest, g_szTempDirectory);
    k = _strlen(szDest);
    _strcat(szDest, NTOSKRNMP_EXE);

    if (!CopyFile(szSource, szDest, FALSE))
        return FALSE;

    if (IsEFI != FALSE) {
        _strcpy(&szSource[l], WINLOAD_EFI);
        _strcpy(&szDest[k], OSLOAD_EFI);
    }
    else {
        _strcpy(&szSource[l], WINLOAD_EXE);
        _strcpy(&szDest[k], OSLOAD_EXE);
    }
    if (!CopyFile(szSource, szDest, FALSE))
        return FALSE;

    return TRUE;
}

/*
* supMapFile
*
* Purpose:
*
* Map file into memory and return pointer to section describing mapping.
* Caller free memory with NtUnmapViewOfSection after use.
*
*/
PVOID supMapFile(
    _In_ LPWSTR lpFileName,
    _Out_ PSIZE_T VirtualSize
)
{
    BOOLEAN             bCond = FALSE, bSuccess = FALSE;
    NTSTATUS            status;
    HANDLE              hFile = NULL, hSection = NULL;
    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;

    RtlSecureZeroMemory(&usFileName, sizeof(usFileName));

    if (VirtualSize)
        *VirtualSize = 0;

    do {

        if (!RtlDosPathNameToNtPathName_U(lpFileName, &usFileName, NULL, NULL)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        }

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_READ_DATA,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            break;
        }

        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            break;
        }

        DllBase = NULL;
        DllVirtualSize = 0;
        status = NtMapViewOfSection(hSection, NtCurrentProcess(), &DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            break;
        }

        bSuccess = TRUE;

        if (VirtualSize)
            *VirtualSize = DllVirtualSize;

    } while (bCond);

    if (usFileName.Buffer != NULL)
        RtlFreeUnicodeString(&usFileName);

    if (hSection != NULL)
        NtClose(hSection);

    if (hFile != NULL)
        NtClose(hFile);

    if (bSuccess == FALSE) {
        if (DllBase != NULL)
            NtUnmapViewOfSection(NtCurrentProcess(), DllBase);
    }

    return DllBase;
}

/*
* supLdrQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                   status;
    ULONG_PTR                  IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY  *DataEntry;
    PBYTE                      Data = NULL;
    ULONG                      SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, &Data, &SizeOfData);
            if (NT_SUCCESS(status)) {
                if (DataSize) {
                    *DataSize = SizeOfData;
                }
            }
        }
    }
    return Data;
}

/*
* supExtractSymDllsToTemp
*
* Purpose:
*
* Extract DbgHelp, SymSrv dlls from application resource to %temp%.
*
*/
BOOL supExtractSymDllsToTemp(
    VOID
)
{
    BOOL bResult = FALSE, bCond = FALSE;

    SIZE_T Length = 0;
    HANDLE hFile;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    PVOID Resource;
    ULONG DataSize, bytesIO;

    WCHAR szExtractFileName[MAX_PATH * 2];

    do {

        DataSize = 0;
        Resource = supLdrQueryResourceData(
            IDR_DBGHELP,
            hInstance,
            &DataSize);

        if (Resource == NULL) {
            SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
            return FALSE;
        }

        _strcpy(szExtractFileName, g_szTempDirectory);
        Length = _strlen(szExtractFileName);
        _strcat(szExtractFileName, TEXT("dbghelp.dll"));

        hFile = CreateFile(szExtractFileName, GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            bResult = WriteFile(hFile, Resource, DataSize, &bytesIO, NULL);
            CloseHandle(hFile);
        }
        if (!bResult)
            break;

        DataSize = 0;
        Resource = supLdrQueryResourceData(
            IDR_SYMSRV,
            hInstance,
            &DataSize);

        if (Resource == NULL) {
            SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
            return FALSE;
        }

        szExtractFileName[Length] = 0;
        _strcat(szExtractFileName, TEXT("symsrv.dll"));
        hFile = CreateFile(szExtractFileName, GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            bResult = WriteFile(hFile, Resource, DataSize, &bytesIO, NULL);
            CloseHandle(hFile);
        }

    } while (bCond);

    return bResult;
}

/*
* supChkSum
*
* Purpose:
*
* Calculate partial checksum for given buffer.
*
*/
USHORT supChkSum(
    ULONG PartialSum,
    PUSHORT Source,
    ULONG Length
)
{
    while (Length--) {
        PartialSum += *Source++;
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
    }
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

/*
* supCheckSumMappedFile
*
* Purpose:
*
* Calculate PE file checksum and set it in PE header.
*
*/
BOOLEAN supCheckSumMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
)
{
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT PartialSum;
    ULONG HeaderSum;
    ULONG CheckSum;

    HeaderSum = 0;
    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders != NULL) {
        HeaderSum = NtHeaders->OptionalHeader.CheckSum;
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
        CheckSum = (ULONG)PartialSum + FileLength;
        NtHeaders->OptionalHeader.CheckSum = CheckSum;
        return TRUE;
    }
    return FALSE;
}

/*
* supPatchFile
*
* Purpose:
*
* Modify binary with patches.
*
*/
BOOL supPatchFile(
    _In_ LPWSTR lpFileName,
    _In_ ULONG_PTR *PatchContext,
    _In_ ULONG NumberOfPatches
)
{
    BOOLEAN bResult = FALSE, bCond = FALSE;
    ULONG i;
    DWORD bytesIO, k, lastError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    PBYTE FileBuffer = NULL;
    LARGE_INTEGER li;

    PATCH_CONTEXT *Context;

    do {

        //
        // Read file to buffer.
        //
        hFile = CreateFile(
            lpFileName,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            lastError = GetLastError();
            break;
        }

        li.QuadPart = 0;
        if (!GetFileSizeEx(hFile, &li)) {
            lastError = GetLastError();
            break;
        }

        FileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, li.LowPart);

        if (FileBuffer == NULL) {
            lastError = GetLastError();
            break;
        }

        if (!ReadFile(hFile, FileBuffer, li.LowPart, &bytesIO, NULL)) {
            lastError = GetLastError();
            break;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        __try {

            //
            // Patch binary.
            //
            for (i = 0; i < NumberOfPatches; i++) {

                Context = (PATCH_CONTEXT*)PatchContext[i];
                RtlCopyMemory(
                    &FileBuffer[Context->AddressOfPatch],
                    Context->PatchData,
                    Context->SizeOfPatch);

            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            lastError = GetExceptionCode();
            break;
        }

        //
        // Update PE header checksum.
        //       
        if (!supCheckSumMappedFile(FileBuffer, li.LowPart)) {
            lastError = ERROR_DATA_CHECKSUM_ERROR;
            break;
        }

        //
        // Overwrite file.
        //
        hFile = CreateFile(
            lpFileName,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_FLAG_WRITE_THROUGH,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            lastError = GetLastError();
            break;
        }

        k = 0;
        if (!WriteFile(hFile, FileBuffer, bytesIO, &k, NULL)) {
            lastError = GetLastError();
            break;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        bResult = (k == bytesIO);
        lastError = ERROR_SUCCESS;

    } while (bCond);

    if (FileBuffer)
        HeapFree(GetProcessHeap(), 0, FileBuffer);

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    SetLastError(lastError);
    return bResult;
}

/*
* supRunProcessWithParamsAndWait
*
* Purpose:
*
* Start process with given arguments and wait until it close.
*
*/
BOOL supRunProcessWithParamsAndWait(
    _In_ LPWSTR lpszParameters,
    _Out_ PDWORD ExitCode
)
{
    BOOL bResult = FALSE;
    LPWSTR pszBuffer = NULL;
    SIZE_T ccb;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    if (ExitCode)
        *ExitCode = (DWORD)-1;

    if (lpszParameters == NULL)
        return bResult;

    ccb = (1 + _strlen(lpszParameters)) * sizeof(WCHAR);
    pszBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ccb);
    if (pszBuffer == NULL)
        return bResult;

    _strcpy(pszBuffer, lpszParameters);

    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    GetStartupInfo(&si);

    bResult = CreateProcess(NULL,
        pszBuffer,
        NULL,
        NULL,
        FALSE,
        CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi);

    if (bResult) {
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, ExitCode);
        CloseHandle(pi.hProcess);
    }

    HeapFree(GetProcessHeap(), 0, pszBuffer);

    return bResult;
}

/*
* supDisablePeAuthAutoStart
*
* Purpose:
*
* Change PEAUTH service startup type from Auto to OnDemand.
*
*/
BOOL supDisablePeAuthAutoStart(
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

/*
* supQueryNtBuildNumber
*
* Purpose:
*
* Query NtBuildNumber value from ntoskrnl image.
*
*/
BOOL supQueryNtBuildNumber(
    _Inout_ PULONG BuildNumber
)
{
    BOOL bResult = FALSE;
    HMODULE hModule;
    PVOID Ptr;
    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szBuffer, L"\\system32\\ntoskrnl.exe");

    hModule = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL)
        return bResult;

#pragma warning(push)
#pragma warning(disable: 4054)//code to data
    Ptr = (PVOID)GetProcAddress(hModule, "NtBuildNumber");
#pragma warning(pop)
    if (Ptr) {
        *BuildNumber = (*(PULONG)Ptr & 0xffff);
        bResult = TRUE;
    }
    FreeLibrary(hModule);
    return bResult;
}
