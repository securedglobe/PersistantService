/*
SG_RevealerService
by Michael Haephrati haephrati@gmail.com
Secured Globe Persistant Windows Service
©2019-2022 Secured Globe, Inc.
https://www.securedglobe.net

Explained in https://www.codeproject.com/Articles/5345258/Thank-You-for-Your-Service-Creating-a-Persistent-I

version 2.0	Nov 2022
*/

#pragma once

// Customizable values
#define SERVICE_NAME				_T("SG_RevealerService")// Service name
#define SERVICE_COMMAND_INSTALL		L"Install"				// The command line argument for installing the service

#define SERVICE_COMMAND_Launcher	L"ServiceIsLauncher"	// Launcher command for NT service
#define MAIN_CLASS_NAME				L"ServiceClass"			// Window class name for service client

#define MAIN_TIMER_ID				2001


void WriteToLog(LPCTSTR lpText, ...);

void ReportServiceStatus(DWORD, DWORD, DWORD);
void WINAPI InstallService();
void ImpersonateActiveUserAndRun(WCHAR* path, WCHAR* args);
std::wstring GetLoggedInUser();
void WINAPI ServiceMain(DWORD dwArgCount, LPTSTR lpszArgValues[]);
DWORD WINAPI CtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID pEventData, LPVOID pUserData);
DWORD WINAPI AppMainFunction();
BOOL RunHost(LPWSTR HostExePath,LPWSTR CommandLineArguments);
LRESULT CALLBACK S_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);


