/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       MAIN.C
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

fnptr_snwprintf_s _snwprintf_s;

HANDLE      g_ConOut = NULL;
HANDLE      g_ConIn = NULL;
BOOL        g_ConsoleOutput = FALSE;
BOOL        g_IsEFI = FALSE;
WCHAR       g_BE = 0xFEFF;

WCHAR       g_szTempDirectory[MAX_PATH + 1];
WCHAR       g_szSystemDirectory[MAX_PATH + 1];
WCHAR       g_szDeviceParition[MAX_PATH + 1];

//
// Ntoskrnl patch points
//

//dse
PATCH_CONTEXT SeValidateImageData;
PATCH_CONTEXT SepInitializeCodeIntegrity;

//pg macro call
PATCH_CONTEXT CcInitializeBcbProfiler;

//pg initializer
PATCH_CONTEXT KiFilterFiberContext;

//pg initialization points
PATCH_CONTEXT KeInitAmd64SpecificState; //seh->KiFilterFiberContext
PATCH_CONTEXT ExpLicenseWatchInitWorker; //pcr->prcb->KiFilterFiberContext

//
// Winload patch points
//

//image validation
PATCH_CONTEXT ImgpValidateImageHash;


/*
* ScanNtos
*
* Purpose:
*
* Search for required patterns in ntoskrnl.exe.
*
*/
BOOLEAN ScanNtos(
    _In_ BOOLEAN EnableFiberContextPatch
)
{
    BOOLEAN             bCond = FALSE, bResult = FALSE, fUseSymbols = FALSE;
    ULONG               MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;

    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    IMAGE_NT_HEADERS   *NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szVersion[MAX_PATH];


    do {


#ifndef _DEBUG
        _strcpy(szBuffer, g_szTempDirectory);
        _strcat(szBuffer, NTOSKRNMP_EXE);
#else 
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.1.7601.18471\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.1.7601.23418\\ntoskrnl.exe");
        _strcpy(szBuffer, L"D:\\dumps\\pgos\\6.1.7601.24059\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.2.9200.16384\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.3.9600.18589\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.10240.16384\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.10586.0\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.14393.0\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.15063.0\\ntoskrnl.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.16299.15\\ntoskrnl.exe");
#endif

        if (!supGetBinaryVersionNumbers(
            szBuffer,
            &MajorVersion,
            &MinorVersion,
            &BuildNumber,
            &Revision))
        {
            supShowError(ERROR_VERSION_PARSE_ERROR, TEXT("Cannot query ntoskrnl version information"));
            break;
        }

        //
        // Output ntorknrl version.
        //
        RtlSecureZeroMemory(szVersion, sizeof(szVersion));

        _snwprintf_s(szVersion, MAX_PATH, MAX_PATH, L"Patch: Ntoskrnl version: %lu.%lu.%lu.%lu\n",
            MajorVersion,
            MinorVersion,
            BuildNumber,
            Revision);

        cuiPrintText(g_ConOut, szVersion, g_ConsoleOutput, TRUE);

        //
        // Map ntos image.
        //
        DllBase = supMapFile(szBuffer, &DllVirtualSize);
        if (DllBase == NULL) {
            supShowError(GetLastError(), TEXT("Cannot map ntos file"));
            break;
        }

        NtHeaders = RtlImageNtHeader(DllBase);

        fUseSymbols = (BOOLEAN)SymbolsLoadForFile(szBuffer, (DWORD64)DllBase);

        if (fUseSymbols != TRUE) {
            supShowError(GetLastError(), TEXT("Cannot load symbols for the ntoskrnl, signatures now used"));
        }
        
        //
        // Scan for SeValidateImageData
        //
        if (!QuerySeValidateImageDataOffset(
            BuildNumber,
            Revision,
            DllBase,
            DllVirtualSize,
            NtHeaders,
            &SeValidateImageData))
        {
            supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SeValidateImageData offset"));
            break;
        }

        _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SeValidateImageData\t\t%08llX"), //-V111
            SeValidateImageData.AddressOfPatch);
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        //
        // Scan for CcInitializeBcbProfiler
        //
        if (!QueryCcInitializeBcbProfilerOffset(
            BuildNumber,
            Revision,
            DllBase,
            DllVirtualSize,
            NtHeaders,
            &CcInitializeBcbProfiler))
        {
            supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query CcInitializeBcbProfiler offset"));
            break;
        }

        _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> CcInitializeBcbProfiler\t%08llX"), //-V111
            CcInitializeBcbProfiler.AddressOfPatch);
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        //
        // Scan for KiFilterFiberContext if enabled by command.
        //
        if (EnableFiberContextPatch) {

            if (!QueryKiFilterFiberContextOffset(
                BuildNumber,
                Revision,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &KiFilterFiberContext))
            {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query KiFilterFiberContext offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> KiFilterFiberContext\t\t%08llX"), //-V111
                KiFilterFiberContext.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        }
        else {

            //
            // KiFilterFiberContext patch disabled.
            //
            // Scan for KeInitAmd64SpecificState
            //
            if (!QueryKeInitAmd64SpecificStateOffset(
                BuildNumber,
                Revision,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &KeInitAmd64SpecificState))
            {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query KeInitAmd64SpecificState offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> KeInitAmd64SpecificState\t%08llX"), //-V111
                KeInitAmd64SpecificState.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            //
            // Scan for ExpLicenseWatchInitWorker
            // Not exist on Windows 7.
            //
            if (BuildNumber > 7601) {

                if (!QueryExpLicenseWatchInitWorkerOffset(
                    BuildNumber,
                    Revision,
                    DllBase,
                    DllVirtualSize,
                    NtHeaders,
                    &ExpLicenseWatchInitWorker))
                {
                    supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query ExpLicenseWatchInitWorker offset"));
                    break;
                }
                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ExpLicenseWatchInitWorker\t%08llX"), //-V111
                    ExpLicenseWatchInitWorker.AddressOfPatch);
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            }

        }

        //
        //Scan for SepInitializeCodeIntegrity
        //
        if (!QuerySepInitializeCodeIntegrityOffset(
            BuildNumber,
            Revision,
            DllBase,
            DllVirtualSize,
            NtHeaders,
            &SepInitializeCodeIntegrity))
        {
            supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SepInitializeCodeIntegrity offset"));
            break;
        }

        _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SepInitializeCodeIntegrity\t%08llX"), //-V111
            SepInitializeCodeIntegrity.AddressOfPatch);
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        bResult = TRUE;

    } while (bCond);

    if (fUseSymbols)
        SymbolsUnload((DWORD64)DllBase);

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
    ULONG               MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;

    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    IMAGE_NT_HEADERS   *NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szVersion[MAX_PATH];


    do {

#ifndef _DEBUG
        _strcpy(szBuffer, g_szTempDirectory);
        if (g_IsEFI != FALSE) {
            _strcat(szBuffer, OSLOAD_EFI);
        }
        else {
            _strcat(szBuffer, OSLOAD_EXE);
        }
#else
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.1.7601.23418\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.2.9200.16384\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\6.3.9600.18589\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.10240.16384\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.10586.0\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.14393.0\\winload.exe");
        //_strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.15063.0\\winload.exe");
        _strcpy(szBuffer, L"D:\\dumps\\pgos\\10.0.16299.15\\winload.exe");
#endif

        if (!supGetBinaryVersionNumbers(
            szBuffer,
            &MajorVersion,
            &MinorVersion,
            &BuildNumber,
            &Revision))
        {
            supShowError(ERROR_VERSION_PARSE_ERROR, TEXT("Cannot query winload build number"));
            break;
        }

        //
        // Output winload version.
        //
        RtlSecureZeroMemory(szVersion, sizeof(szVersion));

        _snwprintf_s(szVersion, MAX_PATH, MAX_PATH, L"Patch: Winload version: %lu.%lu.%lu.%lu\n",
            MajorVersion,
            MinorVersion,
            BuildNumber,
            Revision);

        cuiPrintText(g_ConOut, szVersion, g_ConsoleOutput, TRUE);

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

            if (QueryImgpValidateImageHashOffsetSymbols(
                DllBase,
                NtHeaders,
                &ImgpValidateImageHash))
            {
                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ImgpValidateImageHash\t%08llX"), //-V111
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

            bResult = QueryImgpValidateImageHashOffsetSignatures(
                BuildNumber,
                Revision,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &ImgpValidateImageHash);

            if (bResult) {
                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ImgpValidateImageHash\t%08llX"), //-V111
                    ImgpValidateImageHash.AddressOfPatch);

                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
            }
            else {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query ImgpValidateImageHash offset using signatures"));
            }
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
    _In_ BOOLEAN EnableFiberContextPatch
)
{
    ULONG NumberOfPatches;
    SIZE_T DestLength;
    ULONG_PTR PatchContext[MAX_PATCH_COUNT];
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

    NumberOfPatches = 0;
    PatchContext[NumberOfPatches++] = (ULONG_PTR)&SeValidateImageData;
    PatchContext[NumberOfPatches++] = (ULONG_PTR)&CcInitializeBcbProfiler;
    PatchContext[NumberOfPatches++] = (ULONG_PTR)&SepInitializeCodeIntegrity;

    if (EnableFiberContextPatch) {
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&KiFilterFiberContext;
    }
    else {
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&KeInitAmd64SpecificState;
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&ExpLicenseWatchInitWorker;
    }

    if (!supPatchFile(szBuffer, (ULONG_PTR*)&PatchContext, NumberOfPatches))
        return FALSE;

    if (!MoveFileEx(szBuffer,
        szDest,
        MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
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
        MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        return FALSE;
    }

    return TRUE;
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
    BOOL AlreadyInstalled = FALSE;
    BOOLEAN bCond = FALSE;
    BOOLEAN bEnabled = FALSE;
    BOOLEAN EnableFiberContextPatch = FALSE;
    DWORD l = 0;
    FIRMWARE_TYPE FirmwareType;
    OSVERSIONINFO osver;
    INPUT_RECORD inp1;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    ULONG NtBuildNumber = 0;

    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&osver, sizeof(osver));
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

        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &l, NULL);
        }

        cuiClrScr(g_ConOut);
        cuiPrintText(g_ConOut, PROGRAMFULLNAME, g_ConsoleOutput, TRUE);

        //
        // Detect compat mode, compare PEB fields data with ntoskrnl hardcoded values.
        //
        if (!supQueryNtBuildNumber(&NtBuildNumber)) {
            cuiPrintText(g_ConOut,
                TEXT("\n\rCannot query NtBuildNumber value, abort.\n\r"),
                g_ConsoleOutput,
                TRUE);

            break;
        }

        if (osver.dwBuildNumber != NtBuildNumber) {
            
            _strcpy(szBuffer, TEXT("\n\rApplication Compatibility Mode is active.\n\rDisable it for this application."));
            
            cuiPrintText(g_ConOut,
                szBuffer,
                g_ConsoleOutput,
                TRUE);

            break;
        }

        //
        // Check if patch already installed.
        //
        if (BcdPatchEntryAlreadyExist(BCD_PATCH_ENTRY_GUID, &AlreadyInstalled)) {

            if (AlreadyInstalled) {

                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                _strcpy(szBuffer, TEXT("Patch: Boot entry already present, remove it to run this patch again if needed.\n\r"));
                _strcat(szBuffer, TEXT("Removal: Launch elevated command prompt and use the following command ->\n\r"));
                _strcat(szBuffer, TEXT("bcdedit /delete "));
                _strcat(szBuffer, BCD_PATCH_ENTRY_GUID);

                cuiPrintText(g_ConOut,
                    szBuffer,
                    g_ConsoleOutput,
                    TRUE);

                break;
            }
        }

        //
        // Query optional command.
        // Enable KiFilterFiberContext patch and don't use instead two PG initialization points patch.
        // Required for tests.
        //
        l = 0;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, (LPWSTR)&szBuffer, MAX_PATH * sizeof(WCHAR), &l);
        EnableFiberContextPatch = (_strcmpi(szBuffer, TEXT("-pf")) == 0);

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

#ifndef _DEBUG
        l = 0;
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ReadConsole(g_ConIn, &szBuffer, MAX_PATH, &l, NULL);
        if (_strncmp(szBuffer, CONTINUE_CMD, _strlen(CONTINUE_CMD)) != 0)
            break;
#endif

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

        _strcpy(szBuffer, PROGRAMTITLE);
        if (g_IsEFI) 
            _strcat(szBuffer, TEXT(" * EFI Boot"));
        else
            _strcat(szBuffer, TEXT(" * Legacy Boot"));
        
        SetConsoleTitle(szBuffer);

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
        if ((osver.dwBuildNumber < (DWORD)MIN_SUPPORTED_NT_BUILD) ||
            (osver.dwBuildNumber > (DWORD)MAX_SUPPORTED_NT_BUILD))
        {
            cuiPrintText(g_ConOut, TEXT("Patch: Unsupported Windows version."), g_ConsoleOutput, TRUE);
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
            cuiPrintText(g_ConOut, TEXT("Patch: Make sure %TEMP% folder is writeable."), g_ConsoleOutput, TRUE);
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
        cuiPrintText(g_ConOut, TEXT("Patch: Copy files to %TEMP%."), g_ConsoleOutput, TRUE);
        if (!supMakeCopyToTemp(g_IsEFI)) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot copy files to the %TEMP% folder."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Patch: Copy success."), g_ConsoleOutput, TRUE);
        }

        //
        // Scan ntoskrnl for patch patterns.
        //
        cuiPrintText(g_ConOut, TEXT("Patch: Scanning ntoskrnl for patterns.\n"), g_ConsoleOutput, TRUE);
        if (!ScanNtos(EnableFiberContextPatch)) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot locate patch offsets for ntoskrnl."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: Ntoskrnl scan complete."), g_ConsoleOutput, TRUE);
        }

        //
        // Scan winload for patch patterns.
        //
        cuiPrintText(g_ConOut, TEXT("Patch: Scanning winload for patterns.\n"), g_ConsoleOutput, TRUE);
        if (!ScanWinload()) {
            cuiPrintText(g_ConOut, TEXT("Patch: Cannot locate patch offsets for winload."), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: Winload scan complete."), g_ConsoleOutput, TRUE);
        }

#ifdef _DEBUG
        return 0;
#endif

        //
        // Modify files and move them to %systemroot%\system32.
        //
        if (!ModifyFilesAndMove(EnableFiberContextPatch)) {
            supShowError(GetLastError(), TEXT("\nModifyFilesAndMove failed"));
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: ModifyFilesAndMove succeed"), g_ConsoleOutput, TRUE);
        }

        //
        // Setup new BCD entry.
        //
        if (!BcdCreatePatchEntry(osver.dwBuildNumber)) {
            supShowError(GetLastError(), TEXT("\nBcdCreatePatchEntry failed"));
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("\nPatch: BcdCreatePatchEntry succeed"), g_ConsoleOutput, TRUE);
        }

    } while (bCond);

    cuiPrintText(g_ConOut, TEXT("Patch: Press Enter to exit"), g_ConsoleOutput, TRUE);

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
