/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       CUI.C
*
*  VERSION:     1.02
*
*  DATE:        21 Apr 2017
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* cuiClrScr
*
* Purpose:
*
* Clear screen.
*
*/
VOID cuiClrScr(
    _In_ HANDLE hConsole
)
{
    COORD coordScreen;
    DWORD cCharsWritten;
    DWORD dwConSize;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    coordScreen.X = 0;
    coordScreen.Y = 0;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;

    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(hConsole, TEXT(' '),
        dwConSize, coordScreen, &cCharsWritten))
        return;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;

    if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes,
        dwConSize, coordScreen, &cCharsWritten))
        return;

    SetConsoleCursorPosition(hConsole, coordScreen);
}

/*
* cuiPrintText
*
* Purpose:
*
* Output text to the console or file.
*
*/
VOID cuiPrintText(
    _In_ HANDLE hOutConsole,
    _In_ LPWSTR lpText,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn
)
{
    SIZE_T consoleIO;
    DWORD bytesIO;
    LPWSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen(lpText);
    if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
        return;

    consoleIO = consoleIO * sizeof(WCHAR) + 4 + sizeof(UNICODE_NULL);
    Buffer = (LPWSTR)RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, consoleIO);
    if (Buffer) {

        _strcpy(Buffer, lpText);
        if (UseReturn) _strcat(Buffer, TEXT("\r\n"));

        consoleIO = _strlen(Buffer);

        if (ConsoleOutputEnabled != FALSE) {
            WriteConsole(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            WriteFile(hOutConsole, Buffer, (DWORD)(consoleIO * sizeof(WCHAR)), &bytesIO, NULL);
        }
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Buffer);
    }
}
