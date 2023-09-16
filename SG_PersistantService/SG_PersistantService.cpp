/*
SG_PersistantService
by Michael Haephrati haephrati@gmail.com
Secured Globe Persistant Windows Service
©2019-2022 Secured Globe, Inc.
https://www.securedglobe.net

Explained in https://www.codeproject.com/Articles/5345258/Thank-You-for-Your-Service-Creating-a-Persistent-I

version 2.0	Nov 2022
*/
#include "stdafx.h"
#include "SG_PersistantService.h"
#pragma comment(lib, "wevtapi.lib")


#define BUFFER_SIZE				1024
#define DATETIME_BUFFER_SIZE	80
#define SERVICE_REG_KEY			L"SOFTWARE\\SG_PersistantService"
#define SERVICE_KEY_NAME		L"Path"
#define EVENT_SUBSCRIBE_PATH	L"Security"
#define EVENT_SUBSCRIBE_QUERY	L"Event/System[EventID=4624]"
#define LOG_FILE_NAME			L"log.txt"


SERVICE_STATUS					serviceStatus;
SERVICE_STATUS_HANDLE			hServiceStatus;
HWND hWnd = NULL;
HANDLE hPrevAppProcess =		NULL;
HANDLE ghSvcStopEvent =			NULL;

std::wstring m_szExeToFind{L""};//The executable file name without the path (to be found in the process list)
std::wstring m_szExeToRun{L""};	//The executable full path to be launched by the Service
bool g_bLoggedIn = false;		// Is there a logged in user?



// A class for handling subscription to the logon event and waiting for the user to log in
class UserLoginListner
{
	HANDLE hWait = NULL;
	HANDLE hSubscription = NULL;

public:
	~UserLoginListner()
	{
		CloseHandle(hWait);
		EvtClose(hSubscription);
	}

	UserLoginListner()
	{
		const wchar_t* pwsPath = EVENT_SUBSCRIBE_PATH;
		const wchar_t* pwsQuery = EVENT_SUBSCRIBE_QUERY;

		hWait = CreateEvent(NULL, FALSE, FALSE, NULL);

		hSubscription = EvtSubscribe(NULL, NULL,
			pwsPath, pwsQuery,
			NULL,
			hWait,
			(EVT_SUBSCRIBE_CALLBACK)UserLoginListner::SubscriptionCallback,
			EvtSubscribeToFutureEvents);
		if (hSubscription == NULL)
		{
			DWORD status = GetLastError();

			if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
				WriteToLog(L"Channel %s was not found.\n", pwsPath);
			else if (ERROR_EVT_INVALID_QUERY == status)
				WriteToLog(L"The query \"%s\" is not valid.\n", pwsQuery);
			else
				WriteToLog(L"EvtSubscribe failed with %lu.\n", status);

			CloseHandle(hWait);
		}
	}

	// Wait until a user logs in
	void WaitForUserToLogIn()
	{
		WriteToLog(L"Waiting for a user to log in...");
		WaitForSingleObject(hWait, INFINITE);
		WriteToLog(L"Received a Logon event - a user has logged in");
	}

	// The subscription callback function
	static DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
	{
		if (action == EvtSubscribeActionDeliver)
		{
			WriteToLog(L"SubscriptionCallback invoked.");
			HANDLE Handle = (HANDLE)(LONG_PTR)pContext;
			SetEvent(Handle);
		}

		return ERROR_SUCCESS;
	}
};


// A helper function to redirect output from printf / wprintf to the Console
void enableConsole()
{
	//debug console
	AllocConsole();
	AttachConsole(GetCurrentProcessId());
	HWND Handle = GetConsoleWindow();
	// Make the Console window transparent
	SetWindowLong(Handle, GWL_EXSTYLE, GetWindowLong(Handle, GWL_EXSTYLE) | WS_EX_LAYERED);
	// Opacity = 0.5 = (255/2)
	SetLayeredWindowAttributes(Handle, 0, 170, LWA_ALPHA);

	freopen("CON", "w", stdout);
}

/**
 * GetExePath() - returns the full path of the current executable.
 *
 * @param values - none.
 * @return a std::wstring containing the full path of the current executable. 
 */
std::wstring GetExePath()
{
	wchar_t buffer[65536];
	GetModuleFileName(NULL, buffer, sizeof(buffer) / sizeof(*buffer));
	int pos = -1;
	int index = 0;
	while (buffer[index])
	{
		if (buffer[index] == L'\\' || buffer[index] == L'/')
		{
			pos = index;
		}
		index++;
	}
	buffer[pos + 1] = 0;
	return buffer;
}

/**
 * WriteToLog() - writes formatted text into a log file, and on screen (console)
 *
 * @param values - formatted text, such as L"The result is %d",result.
 * @return - none
 */
void WriteToLog(LPCTSTR lpText, ...)
{
	FILE *fp;
	wchar_t log_file[MAX_PATH]{L""};
	if(wcscmp(log_file,L"") == NULL) 
	{
		wcscpy_s(log_file,GetExePath().c_str());
		wcscat_s(log_file,LOG_FILE_NAME);
	}
	// find gmt time, and store in buf_time
	time_t rawtime;
	struct tm* ptm;
	wchar_t buf_time[DATETIME_BUFFER_SIZE];
	time(&rawtime);
	ptm = gmtime(&rawtime);
	wcsftime(buf_time, sizeof(buf_time) / sizeof(*buf_time), L"%d.%m.%Y %H:%M", ptm);

	// store passed messsage (lpText) to buffer_in
	wchar_t buffer_in[BUFFER_SIZE];

	va_list ptr;
	va_start(ptr, lpText);

	vswprintf(buffer_in, BUFFER_SIZE, lpText, ptr);
	va_end(ptr);


	// store output message to buffer_out - enabled multiple parameters in swprintf
	wchar_t buffer_out[BUFFER_SIZE];

	swprintf(buffer_out, BUFFER_SIZE, L"%s %s\n", buf_time, buffer_in);

	_wfopen_s(&fp, log_file, L"a,ccs=UTF-8");
	if (fp)
	{
		fwprintf(fp, L"%s\n", buffer_out);
		fclose(fp);
	}
	wcscat_s(buffer_out,L"\n");HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteConsole(stdOut, buffer_out,(DWORD)wcslen(buffer_out),&written, NULL);
	}
}

/*
* Create Key in registry hive
* @param hKeyParent Parent registry key store under which registry key needs to be created. ex. HKEY_LOCAL_MACHINE
* @param subkey	String value to specify exact location where key needs to be created ex. SOFTWARE\\SG_PersistantService
* @return Status of operation, TRUE if success and FALSE in case of failure
*/
BOOL CreateRegistryKey(HKEY hKeyParent, PWCHAR subkey)
{
	DWORD dwDisposition; //It verify new key is created or open existing key
	HKEY  hKey;
	DWORD Ret;
	Ret =
		RegCreateKeyEx(
			hKeyParent,
			subkey,
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS,
			NULL,
			&hKey,
			&dwDisposition);
	if (Ret != ERROR_SUCCESS)
	{
		WriteToLog(L"Error opening or creating new key\n");
		return FALSE;
	}
	RegCloseKey(hKey); //close the key
	return TRUE;
}

/*
*  Sets the string data of a specified value under a registry key.
*  @param hKeyParent registy key under which subkey to be written ex. HKEY_LOCAL_MACHINE 
*  @param subkey The name of the registry subkey to be opened
*  @param valueName The name of the value to be set
*  @param strData The data to be stored.
*  @return Status of operation, TRUE if success and FALSE in case of failure
*/
BOOL writeStringInRegistry(HKEY hKeyParent, PWCHAR subkey, PWCHAR valueName, PWCHAR strData)
{
	DWORD Ret;
	HKEY hKey;
	//Check if the registry exists
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_WRITE,
		&hKey
	);
	if (Ret == ERROR_SUCCESS)
	{
		if (ERROR_SUCCESS !=
			RegSetValueEx(
				hKey,
				valueName,
				0,
				REG_SZ,
				(LPBYTE)(strData),
				((((DWORD)lstrlen(strData) + 1)) * 2)))
		{
			RegCloseKey(hKey);
			return FALSE;
		}
		RegCloseKey(hKey);
		return TRUE;
	}
	return FALSE;
}

LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
{
	strValue = strDefaultValue;
	TCHAR szBuffer[MAX_PATH];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueEx(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (nError == ERROR_SUCCESS)
	{
		strValue = szBuffer;
		if (strValue.front() == _T('"') && strValue.back() == _T('"'))
		{
			strValue.erase(0, 1); // erase the first character
			strValue.erase(strValue.size() - 1); // erase the last character
		}
	}
	return nError;
}

/*
*  @param hKeyParent registy key under which subkey to be written ex. HKEY_LOCAL_MACHINE
*  @param subkey The name of the registry subkey to be opened
*  @param valueName The name of the value to read
*  @param readData wide string data to read from specified registry valueName
*  @return Status of operation, TRUE if success and FALSE in case of failure
*/
BOOL readStringFromRegistry(HKEY hKeyParent, PWCHAR subkey, PWCHAR valueName, std::wstring& readData)
{
	HKEY hKey;
	DWORD len = 1024;
	DWORD readDataLen = len;
	PWCHAR readBuffer = (PWCHAR)malloc(sizeof(PWCHAR) * len);
	if (readBuffer == NULL)
		return FALSE;
	//Check if the registry exists
	DWORD Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_READ,
		&hKey
	);
	if (Ret == ERROR_SUCCESS)
	{
		Ret = RegQueryValueEx(
			hKey,
			valueName,
			NULL,
			NULL,
			(BYTE*)readBuffer,
			&readDataLen
		);
		while (Ret == ERROR_MORE_DATA)
		{
			// Get a buffer that is big enough.
			len += 1024;
			readBuffer = (PWCHAR)realloc(readBuffer, len);
			readDataLen = len;
			Ret = RegQueryValueEx(
				hKey,
				valueName,
				NULL,
				NULL,
				(BYTE*)readBuffer,
				&readDataLen
			);
		}
		if (Ret != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;;
		}
		readData = readBuffer;
		RegCloseKey(hKey);
		return true;
	}
	else
	{
		return false;
	}
}
/*!
Service main routine.

SG_WinService.exe Install				-	Service installation
SG_WinService.exe ServiceIsLauncher		-	Start the client
*/


// 
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpszCmdLine, int nCmdShow)
{
	LPWSTR command = (LPTSTR)L"";
	int argc;
	std::wstring w_szLogFileName;
	wchar_t **argv = CommandLineToArgvW(::GetCommandLineW(), &argc);
	if (argc > 1)
		command = argv[1];

	enableConsole();

	WriteToLog(L"SG_PersistantService Windows Service: command = '%s'\n\n", command);
	if (::wcsstr(command, SERVICE_COMMAND_INSTALL) != NULL)
	{
		// Obtaining the full path of the service and adding the special service name quotations
		TCHAR szPath[MAX_PATH] = { 0 };
		BOOL status;
		GetModuleFileName(NULL, szPath, MAX_PATH);

		WriteToLog(L"Option 1 - Install");
		// parse argument for get module path
		wchar_t* real_path = wcschr(command, L'#');
		if (real_path)
		{
			real_path++;
			m_szExeToRun = real_path;
		}
		if(PathFileExists(m_szExeToRun.c_str()))
		{
			WriteToLog(L"[WatchDog] Install module path: %s\n", m_szExeToRun.c_str()); 

			status = CreateRegistryKey(HKEY_LOCAL_MACHINE, (PWCHAR)SERVICE_REG_KEY); //create key
			if (status != TRUE)
				WriteToLog(L"Failed to create registry");
			RunHost((LPWSTR)m_szExeToRun.c_str(),(LPWSTR)L"");
			InstallService();
		}
		else
		{
			WriteToLog(L"App to run '%s' doesn't exist",m_szExeToRun.c_str());
		}
	}
	else if (::wcsstr(command, SERVICE_COMMAND_Launcher) != NULL)
	{
		WriteToLog(L"ServiceIsLauncher\n");
		AppMainFunction();
	}
	else // called with no args
	{
		WriteToLog(L"No args\n");

		SERVICE_TABLE_ENTRY serviceTableEntry[] =
		{
			{
				(LPWSTR)SERVICE_NAME,ServiceMain
			},
			{
				NULL, NULL
			}
		};
		StartServiceCtrlDispatcher(serviceTableEntry);
	}

	return 0;
}


DWORD GetServiceProcessID(SC_HANDLE hService)
{
	SERVICE_STATUS_PROCESS  serviceStatus;
	DWORD                   dwBytesNeeded;

	DWORD result = ::QueryServiceStatusEx(hService
		, SC_STATUS_PROCESS_INFO
		, reinterpret_cast<unsigned char*>(&serviceStatus)
		, sizeof(SERVICE_STATUS_PROCESS)
		, &dwBytesNeeded);

	return (result != 0) ? serviceStatus.dwProcessId : 0;
}

/*!
Service installation
*/
void WINAPI InstallService()
{


	// Obtaining the full path of the service and adding the special service name quotations
	TCHAR szServicePath[MAX_PATH] = { _T("\"") };
	TCHAR szPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szPath, MAX_PATH);
	lstrcat(szServicePath, szPath);
	lstrcat(szServicePath, _T("\""));

	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hSCManager)
	{
		return;
	}


	hService = CreateService(hSCManager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS
		| SERVICE_USER_DEFINED_CONTROL | READ_CONTROL
		| WRITE_DAC | WRITE_OWNER, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		szServicePath, NULL, NULL, NULL, NULL, _T(""));

	if (hService == NULL)
	{
		// Service already installed, just open it
		hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
		if (hService == NULL)
		{
			CloseServiceHandle(hSCManager);
			return;
		}
		return;
	}

	SERVICE_DESCRIPTION description = { (LPTSTR)_T("Secured Globe Windows Service")};
	ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &description);

	// Starting the service
	if (!StartService(hService, 0, NULL))
	{
		WriteToLog(L"Error %d\n", ::GetLastError());
	}
	else
	{
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}


/*!
*/
void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	serviceStatus.dwCurrentState = dwCurrentState;
	serviceStatus.dwWin32ExitCode = dwWin32ExitCode;
	serviceStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		serviceStatus.dwControlsAccepted = 0;
	else
		serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;

	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
		serviceStatus.dwCheckPoint = 0;
	else
		serviceStatus.dwCheckPoint = dwCheckPoint++;

	if (dwCurrentState == SERVICE_START_PENDING)
		serviceStatus.dwControlsAccepted = 0;
    else 
	{
		serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        serviceStatus.dwControlsAccepted |= SERVICE_ACCEPT_SESSIONCHANGE;
    }

    if ((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED))
        serviceStatus.dwCheckPoint = 0;
    else serviceStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
	SetServiceStatus(hServiceStatus, &serviceStatus);
}

//Function to run a process as active user from windows service
void ImpersonateActiveUserAndRun()
{
    DWORD session_id = -1;
    DWORD session_count = 0;
    WTS_SESSION_INFOW *pSession = NULL;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSession, &session_count))
    {
		WriteToLog(L"WTSEnumerateSessions - success");
    }
    else
    {
		WriteToLog(L"WTSEnumerateSessions - failed. Error %d",GetLastError());
        return;
    }
    TCHAR szCurModule[MAX_PATH] = { 0 };

    GetModuleFileName(NULL, szCurModule, MAX_PATH);


    for (size_t i = 0; i < session_count; i++)
    {
        session_id = pSession[i].SessionId;
        WTS_CONNECTSTATE_CLASS wts_connect_state = WTSDisconnected;
        WTS_CONNECTSTATE_CLASS* ptr_wts_connect_state = NULL;
        DWORD bytes_returned = 0;
        if (::WTSQuerySessionInformation(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSConnectState,
            reinterpret_cast<LPTSTR*>(&ptr_wts_connect_state),
            &bytes_returned))
        {
            wts_connect_state = *ptr_wts_connect_state;
            ::WTSFreeMemory(ptr_wts_connect_state);
            if (wts_connect_state != WTSActive) continue;
        }
        else
        {
            continue;
        }

        HANDLE hImpersonationToken;
        if (!WTSQueryUserToken(session_id, &hImpersonationToken))
        {
            continue;
        }

        //Get the actual token from impersonation one
        DWORD neededSize1 = 0;
        HANDLE *realToken = new HANDLE;
        if (GetTokenInformation(hImpersonationToken, (::TOKEN_INFORMATION_CLASS) TokenLinkedToken, realToken, sizeof(HANDLE), &neededSize1))
        {
            CloseHandle(hImpersonationToken);
            hImpersonationToken = *realToken;
        }
        else
        {
            continue;
        }
        HANDLE hUserToken;
        if (!DuplicateTokenEx(hImpersonationToken,
            TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS | MAXIMUM_ALLOWED,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hUserToken))
        {
            continue;
        }


        // Get user name of this process
        WCHAR* pUserName;
        DWORD user_name_len = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, WTSUserName, &pUserName, &user_name_len))
        {
            //Now we got the user name stored in pUserName
        }
        // Free allocated memory                         
        if (pUserName) WTSFreeMemory(pUserName);
        ImpersonateLoggedOnUser(hUserToken);
        STARTUPINFOW StartupInfo;
        GetStartupInfoW(&StartupInfo);
        StartupInfo.cb = sizeof(STARTUPINFOW);
        PROCESS_INFORMATION processInfo;
        SECURITY_ATTRIBUTES Security1;
        Security1.nLength = sizeof SECURITY_ATTRIBUTES;
        SECURITY_ATTRIBUTES Security2;
        Security2.nLength = sizeof SECURITY_ATTRIBUTES;
        void* lpEnvironment = NULL;

        // Obtain all needed necessary environment variables of the logged in user.
        // They will then be passed to the new process we create.

        BOOL resultEnv = CreateEnvironmentBlock(&lpEnvironment, hUserToken, FALSE);
        if (!resultEnv)
        {
            WriteToLog(L"CreateEnvironmentBlock - failed. Error %d",GetLastError());
            continue;
        }
        std::wstring commandLine;
        commandLine.reserve(1024);
        commandLine += L"\"";
        commandLine += szCurModule;
        commandLine += L"\" \"";
        commandLine += SERVICE_COMMAND_Launcher;
        commandLine += L"\"";
        WCHAR PP[1024]; //path and parameters
        ZeroMemory(PP, 1024 * sizeof WCHAR);
        wcscpy_s(PP, commandLine.c_str());

        // Next we impersonate - by starting the process as if the current logged in user, has started it
        BOOL result = CreateProcessAsUserW(hUserToken,
            NULL,
            PP,
            NULL,
            NULL,
            FALSE,
            NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &StartupInfo,
            &processInfo);

        if (!result)
        {
            WriteToLog(L"CreateProcessAsUser - failed. Error %d",GetLastError());
        }
        else
        {
            WriteToLog(L"CreateProcessAsUser - success");
        }
        DestroyEnvironmentBlock(lpEnvironment);
        CloseHandle(hImpersonationToken);
        CloseHandle(hUserToken);
        CloseHandle(realToken);
        RevertToSelf();
    }
    WTSFreeMemory(pSession);
}
std::wstring GetLoggedInUser()
{
	std::wstring user{L""};
	WTS_SESSION_INFO *SessionInfo;
	unsigned long SessionCount;
	unsigned long ActiveSessionId = -1;

	//std::cout<<"Active Console Session Id : "<<WTSGetActiveConsoleSessionId()<<"\n";

	if(WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &SessionInfo, &SessionCount))
	{
		for (size_t i = 0; i < SessionCount; i++)
		{
			if (SessionInfo[i].State == WTSActive || SessionInfo[i].State == WTSConnected)
			{
				ActiveSessionId = SessionInfo[i].SessionId;
				break;
			}
		}

		wchar_t *UserName;
		if (ActiveSessionId != -1)
		{
			unsigned long BytesReturned;
			if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, ActiveSessionId, WTSUserName, &UserName, &BytesReturned))
			{
				user = UserName;		// Now we have the logged in user name
				WTSFreeMemory(UserName);	
			}
		}
		WTSFreeMemory(SessionInfo);
	}
	return user;
}

/*!
*/
void WINAPI ServiceMain(DWORD dwArgCount, LPTSTR lpszArgValues[])
{


	ZeroMemory(&serviceStatus, sizeof(SERVICE_STATUS));
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	hServiceStatus = RegisterServiceCtrlHandlerEx(SERVICE_NAME, CtrlHandlerEx, NULL);

	ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 1000);

	// Service stopped event for sync between client and service
	ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (ghSvcStopEvent == NULL)
	{
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	TCHAR szCurModule[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurModule, MAX_PATH);

	WriteToLog(L"Launch client\n"); // launch client ...
	{
		UserLoginListner WaitTillAUserLogins;
		WaitTillAUserLogins.WaitForUserToLogIn();
	}
	ImpersonateActiveUserAndRun();
	

	ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

	while (1)
	{
		// Check whether to stop the service.
		WaitForSingleObject(ghSvcStopEvent, INFINITE);
		CloseHandle(ghSvcStopEvent);
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
}

void WINAPI Run(DWORD dwTargetSessionId, int desktop)
{
	if (hPrevAppProcess != NULL)
	{
		TerminateProcess(hPrevAppProcess, 0);
		WaitForSingleObject(hPrevAppProcess, INFINITE);
	}


	HANDLE hToken = 0;
	WTS_SESSION_INFO *si;
	DWORD cnt = 0;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &cnt);

	// https://www.codeproject.com/Articles/36581/Interaction-between-services-and-applications-at-u
	for (int i = 0; i < (int)cnt; i++)
	{
		if (si[i].SessionId == 0)
		{
			continue;
		}
		HANDLE userToken;
		if (WTSQueryUserToken(si[i].SessionId, &userToken))
		{
			TOKEN_LINKED_TOKEN *admin;
			DWORD dwSize, dwResult;
			// The data area passed to a system call is too small
			// Call GetTokenInformation to get the buffer size.
			if (GetTokenInformation(hToken, TokenLinkedToken, NULL, 0, &dwSize))
			{
				dwResult = GetLastError();
				if (dwResult != ERROR_INSUFFICIENT_BUFFER)
				{
					break;
				}
			}

			// Allocate the buffer.

			admin = (TOKEN_LINKED_TOKEN *)GlobalAlloc(GPTR, dwSize);

			// Call GetTokenInformation again to get the group information.

			if (!GetTokenInformation(hToken, TokenLinkedToken, admin,
				dwSize, &dwSize))
			{
				break;
			}
			else
			{
				hToken = admin->LinkedToken;
				break;
			}
			CloseHandle(userToken);
		}
		else
		{
			DWORD error = GetLastError();
			{
				LPVOID lpMsgBuf;
				DWORD bufLen = FormatMessage(
					FORMAT_MESSAGE_ALLOCATE_BUFFER |
					FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					error,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR)&lpMsgBuf,
					0, NULL);
			}
		}
	}
	if (hToken == 0)
	{
		HANDLE systemToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &systemToken);
		DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hToken);
		CloseHandle(systemToken);
		int i;
		for (i = 0; i < (int)cnt; i++)
		{
			if (si[i].SessionId == 0)continue;
			if (SetTokenInformation(hToken, TokenSessionId, &si[i].SessionId, sizeof(DWORD)))
			{
				break;
			}
		}
	}
	WTSFreeMemory(si);


	STARTUPINFO startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFO);

	startupInfo.lpDesktop = (LPWSTR)L"...";

	LPVOID pEnv = NULL;
	CreateEnvironmentBlock(&pEnv, hToken, TRUE);

	PROCESS_INFORMATION processInfo = {};
	PROCESS_INFORMATION processInfo32 = {};

	TCHAR szCurModule[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurModule, MAX_PATH);

	BOOL bRes = FALSE;

	{
		std::wstring commandLine;
		commandLine.reserve(1024);

		commandLine += L"\"";
		commandLine += szCurModule;
		commandLine += L"\" \"";
		commandLine += SERVICE_COMMAND_Launcher;
		commandLine += L"\"";


		bRes = CreateProcessAsUserW(hToken, NULL, &commandLine[0], NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS |
			CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE, pEnv,
			NULL, &startupInfo, &processInfo);

		if (bRes == FALSE)
		{
			DWORD   dwLastError = ::GetLastError();
			TCHAR   lpBuffer[256] = _T("?");
			if (dwLastError != 0)    // Don't want to see a "operation done successfully" error ;-)
				::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,                 // It磗 a system error
					NULL,                                      // No string to be formatted needed
					dwLastError,                               // Hey Windows: Please explain this error!
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Do it in the standard language
					lpBuffer,              // Put the message here
					255,                     // Number of bytes to store the message
					NULL);
		}
		else
		{
		}
	}
}

/*!
*/
DWORD WINAPI CtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID pEventData, LPVOID pUserData)
{
	switch (dwControl)
	{
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
		{
			if (dwControl == SERVICE_CONTROL_SHUTDOWN)
				WriteToLog(L"SERVICE_CONTROL_SHUTDOWN");
			else
				WriteToLog(L"SERVICE_CONTROL_STOP");
			// Service stopped by the user
			ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
			SetEvent(ghSvcStopEvent);
			ReportServiceStatus(serviceStatus.dwCurrentState, NO_ERROR, 0);
		}
		break;
		case SERVICE_CONTROL_PAUSE:
		{
			WriteToLog(L"SERVICE_CONTROL_PAUSE");
		}
		break;
		case SERVICE_CONTROL_CONTINUE:
		{
			WriteToLog(L"SERVICE_CONTROL_CONTINUE");
		}
		break;
		case SERVICE_CONTROL_INTERROGATE:
		{
			WriteToLog(L"SERVICE_CONTROL_INTERROGATE");
		}
		break;
		case SERVICE_CONTROL_PARAMCHANGE:
		{
			WriteToLog(L"SERVICE_CONTROL_PARAMCHANGE");
		}
		break;
		case SERVICE_CONTROL_NETBINDADD:
		{
			WriteToLog(L"SERVICE_CONTROL_NETBINDADD");
		}
		break;
		case SERVICE_CONTROL_NETBINDREMOVE:
		{
			WriteToLog(L"SERVICE_CONTROL_NETBINDREMOVE");
		}
		break;
		case SERVICE_CONTROL_NETBINDENABLE:
		{
			WriteToLog(L"SERVICE_CONTROL_NETBINDENABLE");
		}
		break;
		case SERVICE_CONTROL_NETBINDDISABLE:
		{
			WriteToLog(L"SERVICE_CONTROL_NETBINDDISABLE");
		}
		break;
		case SERVICE_CONTROL_DEVICEEVENT:
		{
			WriteToLog(L"SERVICE_CONTROL_DEVICEEVENT");
		}
		break;
		case SERVICE_CONTROL_HARDWAREPROFILECHANGE:
		{
			WriteToLog(L"SERVICE_CONTROL_HARDWAREPROFILECHANGE");
		}
		break;
		case SERVICE_CONTROL_POWEREVENT:
		{
			WriteToLog(L"SERVICE_CONTROL_POWEREVENT");
		}
		break;
		case SERVICE_CONTROL_SESSIONCHANGE:
		{
			WriteToLog(L"SERVICE_CONTROL_SESSIONCHANGE");
			switch (dwEventType)
			{
				case WTS_CONSOLE_CONNECT:
				{
					WriteToLog(L"WTS_CONSOLE_CONNECT");
				}
				break;
				case WTS_CONSOLE_DISCONNECT:
				{
					WriteToLog(L"WTS_CONSOLE_DISCONNECT");
				}
				break;
				case WTS_REMOTE_CONNECT:
				{
					WriteToLog(L"WTS_REMOTE_CONNECT");
				}
				break;
				case WTS_REMOTE_DISCONNECT:
				{
					WriteToLog(L"WTS_REMOTE_DISCONNECT");
				}
				break;
				case WTS_SESSION_LOGON:
				{
					// User logon, startup the client app
					WriteToLog(L"WTS_SESSION_LOGON");
					ImpersonateActiveUserAndRun();
				}
				break;
				case WTS_SESSION_LOGOFF:
				{
					WriteToLog(L"WTS_SESSION_LOGOFF");
					// User logoff, the client app has been closed, reset hPrevAppProcess
					hPrevAppProcess = NULL;
				}
				break;
				case WTS_SESSION_LOCK:
				{
					WriteToLog(L"WTS_SESSION_LOCK");
				}
				break;
				case WTS_SESSION_UNLOCK:
				{
					WriteToLog(L"WTS_SESSION_UNLOCK");
				}
				break;
				case WTS_SESSION_REMOTE_CONTROL:
				{
					WriteToLog(L"WTS_SESSION_REMOTE_CONTROL");
				}
				break;
				case WTS_SESSION_CREATE:
				{
					WriteToLog(L"WTS_SESSION_CREATE");
				}
				break;
				case WTS_SESSION_TERMINATE:
				{
					WriteToLog(L"WTS_SESSION_TERMINATE");
				}
				break;
			}
		}
		break;
		case SERVICE_CONTROL_PRESHUTDOWN:
		{
			WriteToLog(L"SERVICE_CONTROL_PRESHUTDOWN");
		}
		break;
		case SERVICE_CONTROL_TIMECHANGE:
		{
			WriteToLog(L"SERVICE_CONTROL_TIMECHANGE");
		}
		break;
		case SERVICE_CONTROL_TRIGGEREVENT:
		{
			WriteToLog(L"SERVICE_CONTROL_TRIGGEREVENT");
		}
		break;
		default:
			return ERROR_CALL_NOT_IMPLEMENTED;
	}

	ReportServiceStatus(serviceStatus.dwCurrentState, NO_ERROR, 0);
	return NO_ERROR;
}


void MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex = { sizeof(wcex) };
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = S_WndProc;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = NULL;
	wcex.hbrBackground = NULL;
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = MAIN_CLASS_NAME;
	RegisterClassEx(&wcex);
}

/*!
Service client main application
*/

DWORD WINAPI AppMainFunction()
{
	//HRESULT w_hRet = S_OK;
	// AppMainFunction start
	WriteToLog(L"AppMainFunction start\n");

	HINSTANCE hInstance = GetModuleHandle(NULL);

	// Setting the working directory to the currect
	// application folder rather than System32
	TCHAR szDirPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szDirPath, MAX_PATH);
	PathRemoveFileSpec(szDirPath);
	SetCurrentDirectory(szDirPath);


	// Registering the main window class
	MyRegisterClass(hInstance);

	// Creating the main window
	hWnd = CreateWindow(MAIN_CLASS_NAME, _T(""), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0,
		CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

	if (hWnd)
	{
		g_bLoggedIn = true;
		SetTimer(hWnd, MAIN_TIMER_ID, 10000, NULL);
		// SG Revealer Service [%S %S] has started
		WriteToLog(L"SG Revealer Service [%S %S] has started\n",
			__DATE__,
			__TIME__);
	}
	else
	{
		// CreateWindow failed
		WriteToLog(L"CreateWindow failed\n");
	}


	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	hWnd = NULL;


	return (DWORD)msg.wParam;
}



/*
RunHost
*/

BOOL RunHost(LPWSTR HostExePath,LPWSTR CommandLineArguments)
{
	WriteToLog(L"RunHost '%s'",HostExePath);

	STARTUPINFO startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPTSTR)_T("winsta0\\default");

	HANDLE hToken = 0;
	BOOL bRes = FALSE;

	LPVOID pEnv = NULL;
	CreateEnvironmentBlock(&pEnv, hToken, TRUE);

	PROCESS_INFORMATION processInfoAgent = {};
	PROCESS_INFORMATION processInfoHideProcess = {};
	PROCESS_INFORMATION processInfoHideProcess32 = {};

	if (PathFileExists(HostExePath))
	{
		std::wstring commandLine;
		commandLine.reserve(1024);


		commandLine += L"\"";
		commandLine += HostExePath;
		commandLine += L"\" \"";
		commandLine += CommandLineArguments;
		commandLine += L"\"";

		WriteToLog(L"launch host with CreateProcessAsUser ...  %s", commandLine.c_str());

		bRes = CreateProcessAsUserW(hToken, NULL, &commandLine[0], NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS |
			CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE, pEnv,
			NULL, &startupInfo, &processInfoAgent);
		if (bRes == FALSE)
		{
			DWORD   dwLastError = ::GetLastError();
			TCHAR   lpBuffer[256] = _T("?");
			if (dwLastError != 0)    // Don't want to see a "operation done successfully" error ;-)
			{
				::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,                 // It´s a system error
					NULL,                                      // No string to be formatted needed
					dwLastError,                               // Hey Windows: Please explain this error!
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Do it in the standard language
					lpBuffer,              // Put the message here
					255,                     // Number of bytes to store the message
					NULL);
			}
			WriteToLog(L"CreateProcessAsUser failed - Command Line = %s Error : %s",commandLine, lpBuffer);
		}
		else
		{
			if (!writeStringInRegistry(HKEY_LOCAL_MACHINE, (PWCHAR)SERVICE_REG_KEY, (PWCHAR)SERVICE_KEY_NAME, HostExePath))
			{
				WriteToLog(L"Failed to write registry");
			}

		}
	}
	else
	{
		WriteToLog(L"RunHost failed because path '%s' does not exists",HostExePath);
	}
	hPrevAppProcess = processInfoAgent.hProcess;
	
	CloseHandle(hToken);
	WriteToLog(L"Run host end!");

	return bRes;
}

/*!
Service client message loop
*/
LRESULT CALLBACK S_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	//int wmId, wmEvent;
	std::wstring drive;
	static HDEVNOTIFY hDeviceNotify;
	static bool is_running{ false };

	switch (message)
	{
		case WM_ENDSESSION:
		case WM_QUERYENDSESSION:
		{
			WriteToLog(L"Logging off\n"); // Logging off
			KillTimer(hWnd, MAIN_TIMER_ID);
			g_bLoggedIn = false;
			//Suspend_FltDrv();
			return 0;
		}

		case WM_TIMER:
		{
			if (is_running) break;
			WriteToLog(L"Timer event");
			is_running = true;
			HANDLE hProcessSnap;
			PROCESSENTRY32 pe32;
			bool found{ false };

			WriteToLog(L"Enumerating all processess...");
			// Take a snapshot of all processes in the system.
			hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hProcessSnap == INVALID_HANDLE_VALUE)
			{
				WriteToLog(L"Failed to call CreateToolhelp32Snapshot(). Error code %d",GetLastError());
				is_running = false;
				return 1;
			}

			// Set the size of the structure before using it.
			pe32.dwSize = sizeof(PROCESSENTRY32);

			// Retrieve information about the first process,
			// and exit if unsuccessful
			if (!Process32First(hProcessSnap, &pe32))
			{
				WriteToLog(L"Failed to call Process32First(). Error code %d",GetLastError());
				CloseHandle(hProcessSnap);          // clean the snapshot object
				is_running=false;
				break;
			}

			// Now walk the snapshot of processes, and
			// display information about each process in turn
			DWORD svchost_parent_pid = 0;
			DWORD dllhost_parent_pid = 0;
			std::wstring szPath = L"";

			if (readStringFromRegistry(HKEY_LOCAL_MACHINE, (PWCHAR)SERVICE_REG_KEY, (PWCHAR)SERVICE_KEY_NAME, szPath))
			{
				m_szExeToFind = szPath.substr(szPath.find_last_of(L"/\\") + 1);	// The process name is the executable name only
				m_szExeToRun = szPath;											// The executable to run is the full path
			}
			else
			{
				WriteToLog(L"Error reading ExeToFind from the Registry");
			}

			do
			{
				if (wcsstr( m_szExeToFind.c_str(), pe32.szExeFile))
				{
					WriteToLog(L"%s is running",m_szExeToFind.c_str());
					found = true;
					is_running=false;
					break;
				}
				if (!g_bLoggedIn)
				{
					WriteToLog(L"WatchDog isn't starting '%s' because user isn't logged in",m_szExeToFind.c_str());
					return 1;
				}
			}
			while (Process32Next(hProcessSnap, &pe32));
			if (!found)
			{
				WriteToLog(L"'%s' is not running. Need to start it",m_szExeToFind.c_str());
				if (!m_szExeToRun.empty())	// Watch Dog start the host app
				{
					if (!g_bLoggedIn)
					{
						WriteToLog(L"WatchDog isn't starting '%s' because user isn't logged in",m_szExeToFind.c_str());
						return 1;
					}
					ImpersonateActiveUserAndRun();

	
					RunHost((LPWSTR)m_szExeToRun.c_str(), (LPWSTR)L"");

				}
				else
				{
					WriteToLog(L"m_szExeToRun is empty");
				}
			}
			CloseHandle(hProcessSnap);
		}
		is_running=false;
		break;
		default: 
			is_running=false;
			return DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}
