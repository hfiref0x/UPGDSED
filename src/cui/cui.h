/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       CUI.H
*
*  VERSION:     1.02
*
*  DATE:        21 Apr 2017
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID cuiClrScr(
    _In_ HANDLE hConsole);

VOID cuiPrintText(
    _In_ HANDLE hOutConsole,
    _In_ LPWSTR lpText,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn);
