/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.10
*
*  DATE:        11 May 2017
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
    _In_ BOOLEAN DisableFiberContextPatch
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

        _strcpy(szBuffer, g_szTempDirectory);
        _strcat(szBuffer, NTOSKRNMP_EXE);

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

        if (SymbolsLoadForFile(szBuffer, (DWORD64)DllBase)) {

            //
            // Scan for SeValidateImageData
            //
            if (!QuerySeValidateImageDataOffsetSymbols(
                BuildNumber,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &SeValidateImageData))
            {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SeValidateImageData offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SeValidateImageData\t\t%08llX"),
                SeValidateImageData.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            //
            // Scan for CcInitializeBcbProfiler
            //
            if (!QueryCcInitializeBcbProfilerOffsetSymbols(
                BuildNumber,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &CcInitializeBcbProfiler))
            {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query CcInitializeBcbProfiler offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> CcInitializeBcbProfiler\t%08llX"),
                CcInitializeBcbProfiler.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            //
            // Scan for KiFilterFiberContext
            // If disabled by command use PG initialization points patch.
            //
            if (DisableFiberContextPatch) {

                //
                // KiFilterFiberContext patch disabled.
                // Scan for KeInitAmd64SpecificState
                //
                if (!QueryKeInitAmd64SpecificStateOffsetSymbols(
                    BuildNumber,
                    DllBase,
                    DllVirtualSize,
                    NtHeaders,
                    &KeInitAmd64SpecificState))
                {
                    supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query KeInitAmd64SpecificState offset"));
                    break;
                }

                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> KeInitAmd64SpecificState\t%08llX"),
                    KeInitAmd64SpecificState.AddressOfPatch);
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

                //
                // Scan for ExpLicenseWatchInitWorker
                //
                if (BuildNumber > 7601) {

                    if (!QueryExpLicenseWatchInitWorkerOffsetSymbols(
                        BuildNumber,
                        DllBase,
                        DllVirtualSize,
                        NtHeaders,
                        &ExpLicenseWatchInitWorker))
                    {
                        supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query ExpLicenseWatchInitWorker offset"));
                        break;
                    }
                    _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ExpLicenseWatchInitWorker\t%08llX"),
                        ExpLicenseWatchInitWorker.AddressOfPatch);
                    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
                }

            }
            else {

                if (!QueryKiFilterFiberContextOffset(
                    BuildNumber,
                    DllBase,
                    DllVirtualSize,
                    NtHeaders,
                    &KiFilterFiberContext))
                {
                    supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query KiFilterFiberContext offset"));
                    break;
                }

                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> KiFilterFiberContext\t\t%08llX"),
                    KiFilterFiberContext.AddressOfPatch);
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
            }

            //
            //Scan for SepInitializeCodeIntegrity
            //
            if (!QuerySepInitializeCodeIntegrityOffsetSymbols(
                BuildNumber,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &SepInitializeCodeIntegrity))
            {
                supShowError(ERROR_CAN_NOT_COMPLETE, TEXT("Cannot query SepInitializeCodeIntegrity offset"));
                break;
            }

            _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> SepInitializeCodeIntegrity\t%08llX"),
                SepInitializeCodeIntegrity.AddressOfPatch);
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

            SymbolsUnload((DWORD64)DllBase);
            bResult = TRUE;
        }
        else {
            supShowError(GetLastError(), TEXT("Cannot load symbols for the ntoskrnl"));
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
    ULONG               MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;

    PBYTE               DllBase = NULL;
    SIZE_T              DllVirtualSize;
    IMAGE_NT_HEADERS   *NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szVersion[MAX_PATH];


    do {

        _strcpy(szBuffer, g_szTempDirectory);
        if (g_IsEFI != FALSE) {
            _strcat(szBuffer, OSLOAD_EFI);
        }
        else {
            _strcat(szBuffer, OSLOAD_EXE);
        }

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
                BuildNumber,
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &ImgpValidateImageHash))
            {
                _snwprintf_s(szBuffer, MAX_PATH * 2, MAX_PATH, TEXT("-> ImgpValidateImageHash\t%08llX"),
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
                DllBase,
                DllVirtualSize,
                NtHeaders,
                &ImgpValidateImageHash);

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
    _In_ BOOLEAN DisableFiberContextPatch
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

    if (DisableFiberContextPatch) {
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&KeInitAmd64SpecificState;
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&ExpLicenseWatchInitWorker;
    }
    else {
        PatchContext[NumberOfPatches++] = (ULONG_PTR)&KiFilterFiberContext;
    }

    if (!supPatchFile(szBuffer, (ULONG_PTR*)&PatchContext, NumberOfPatches))
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
    BOOLEAN DisableFiberContextPatch = FALSE;
    DWORD l = 0;
    FIRMWARE_TYPE FirmwareType;
    OSVERSIONINFO osver;
    INPUT_RECORD inp1;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

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

        SetConsoleTitle(PROGRAMTITLE);
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &l, NULL);
        }

        cuiClrScr(g_ConOut);
        cuiPrintText(g_ConOut, PROGRAMFULLNAME, g_ConsoleOutput, TRUE);

        //
        // Check if patch already installed.
        //
        if (BcdPatchEntryAlreadyExist(BCD_PATCH_ENTRY_GUID, &AlreadyInstalled)) {

            if (AlreadyInstalled) {
                cuiPrintText(g_ConOut,
                    TEXT("Patch: Boot entry already present, remove it to run this patch again if needed."),
                    g_ConsoleOutput,
                    TRUE);

                break;
            }
        }

        //
        // Query optional command.
        // Disable KiFilterFiberContext patch and use instead two PG initialization points patch.
        // Required for tests.
        //
        l = 0;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, (LPWSTR)&szBuffer, MAX_PATH * sizeof(WCHAR), &l);
        DisableFiberContextPatch = (_strcmpi(szBuffer, TEXT("-nf")) == 0);

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
        if (!ScanNtos(DisableFiberContextPatch)) {
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
        if (!ModifyFilesAndMove(DisableFiberContextPatch)) {
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
