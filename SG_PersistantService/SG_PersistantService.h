/*
SG_PersistantService
by Michael Haephrati haephrati@gmail.com
Secured Globe Persistant Windows Service
©2019-2022 Secured Globe, Inc.
https://www.securedglobe.net

Explained in https://www.codeproject.com/Articles/5345258/Thank-You-for-Your-Service-Creating-a-Persistent-I

version 2.0	Nov 2022
*/

#pragma once

// Customizable values
#define SERVICE_NAME				_T("SG_PersistantService")// Service name
#define SERVICE_COMMAND_INSTALL		L"Install"				// The command line argument for installing the service

#define SERVICE_COMMAND_Launcher	L"ServiceIsLauncher"	// Launcher command for NT service
#define MAIN_CLASS_NAME				L"ServiceClass"			// Window class name for service client

#define MAIN_TIMER_ID				2001

extern SERVICE_STATUS serviceStatus;
extern SERVICE_STATUS_HANDLE hServiceStatus;
extern HANDLE ghSvcStopEvent;
extern HANDLE hPrevAppProcess;
extern bool g_bLoggedIn;
extern std::wstring m_szExeToFind;
extern std::wstring m_szExeToRun;

void WriteToLog(LPCTSTR lpText, ...);
std::wstring GetExePath();
BOOL CreateRegistryKey(HKEY hKeyParent, PWCHAR subkey);
BOOL writeStringInRegistry(HKEY hKeyParent, PWCHAR subkey, PWCHAR valueName, PWCHAR strData);
LONG GetStringRegKey(HKEY hKey, const std::wstring& strValueName, std::wstring& strValue, const std::wstring& strDefaultValue);
BOOL readStringFromRegistry(HKEY hKeyParent, PWCHAR subkey, PWCHAR valueName, std::wstring& readData);
DWORD GetServiceProcessID(SC_HANDLE hService);

bool IsInstallCommand(LPCWSTR command);
bool IsLauncherCommand(LPCWSTR command);
std::wstring ParseInstallModulePath(LPCWSTR command);
std::wstring ExtractFileName(const std::wstring& szPath);
std::wstring BuildQuotedServicePath(LPCWSTR szPath);
std::wstring BuildLauncherCommandLine(LPCWSTR szCurModule);
std::wstring BuildHostCommandLine(LPCWSTR hostExePath, LPCWSTR commandLineArguments);

void ReportServiceStatus(DWORD, DWORD, DWORD);
void WINAPI InstallService();
void ImpersonateActiveUserAndRun(WCHAR* path, WCHAR* args);
std::wstring GetLoggedInUser();
void WINAPI ServiceMain(DWORD dwArgCount, LPTSTR lpszArgValues[]);
DWORD WINAPI CtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID pEventData, LPVOID pUserData);
DWORD WINAPI AppMainFunction();
BOOL RunHost(LPWSTR HostExePath,LPWSTR CommandLineArguments);
LRESULT CALLBACK S_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);


