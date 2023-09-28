/*
    Native unit tests for SG_PersistantService helpers.
    These call the production functions; they do not install or start the Windows service.
*/
#include "stdafx.h"
#include "CppUnitTest.h"
#include "SG_PersistantService.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// clang-format off
namespace
{
    const wchar_t kTestSubkey[] = L"Software\\SG_PersistantService_UnitTests";

    void DeleteTestKey()
    {
        RegDeleteTreeW(HKEY_CURRENT_USER, kTestSubkey);
    }

    class TestKeyGuard
    {
    public:
        TestKeyGuard()
        {
            DeleteTestKey();
        }

        ~TestKeyGuard()
        {
            DeleteTestKey();
        }
    };
}

namespace SG_PersistantServiceTests
{
    TEST_CLASS(ServiceNameHelpers)
    {
    public:
        TEST_METHOD(ServiceNameIsPersistentService)
        {
            Assert::AreEqual(L"SG_PersistantService", SERVICE_NAME);
        }

        TEST_METHOD(InstallCommandToken)
        {
            Assert::AreEqual(L"Install", SERVICE_COMMAND_INSTALL);
        }

        TEST_METHOD(LauncherCommandToken)
        {
            Assert::AreEqual(L"ServiceIsLauncher", SERVICE_COMMAND_Launcher);
        }

        TEST_METHOD(ClientWindowClassAndTimer)
        {
            Assert::AreEqual(L"ServiceClass", MAIN_CLASS_NAME);
            Assert::AreEqual(2001, MAIN_TIMER_ID);
        }
    };

    TEST_CLASS(CommandParsing)
    {
    public:
        TEST_METHOD(InstallCommandMatchesBareAndPathForms)
        {
            Assert::IsTrue(IsInstallCommand(L"Install"));
            Assert::IsTrue(IsInstallCommand(L"Install#C:\\Apps\\SampleApp.exe"));
            Assert::IsFalse(IsInstallCommand(L""));
            Assert::IsFalse(IsInstallCommand(L"ServiceIsLauncher"));
        }

        TEST_METHOD(LauncherCommandIsDistinctFromInstall)
        {
            Assert::IsTrue(IsLauncherCommand(L"ServiceIsLauncher"));
            Assert::IsFalse(IsLauncherCommand(L"Install"));
            Assert::IsFalse(IsLauncherCommand(L""));
        }

        TEST_METHOD(ParseInstallModulePathAfterHash)
        {
            Assert::AreEqual(L"C:\\Apps\\SampleApp.exe",
                ParseInstallModulePath(L"Install#C:\\Apps\\SampleApp.exe").c_str());
            Assert::AreEqual(L"", ParseInstallModulePath(L"Install").c_str());
            Assert::AreEqual(L"", ParseInstallModulePath(L"Install#").c_str());
            Assert::AreEqual(L"C:\\a#b.exe",
                ParseInstallModulePath(L"Install#C:\\a#b.exe").c_str());
        }
    };

    TEST_CLASS(PathHelpers)
    {
    public:
        TEST_METHOD(ExtractFileNameFromWindowsAndPosixPaths)
        {
            Assert::AreEqual(L"SampleApp.exe",
                ExtractFileName(L"C:\\Program Files\\SG\\SampleApp.exe").c_str());
            Assert::AreEqual(L"SampleApp.exe",
                ExtractFileName(L"C:/Program Files/SG/SampleApp.exe").c_str());
            Assert::AreEqual(L"SampleApp.exe", ExtractFileName(L"SampleApp.exe").c_str());
            Assert::AreEqual(L"", ExtractFileName(L"").c_str());
        }

        TEST_METHOD(BuildQuotedServiceBinaryPath)
        {
            Assert::AreEqual(L"\"C:\\svc\\SG_PersistantService.exe\"",
                BuildQuotedServicePath(L"C:\\svc\\SG_PersistantService.exe").c_str());
        }

        TEST_METHOD(BuildLauncherCommandLineQuotesModuleAndToken)
        {
            Assert::AreEqual(L"\"C:\\svc\\SG_PersistantService.exe\" \"ServiceIsLauncher\"",
                BuildLauncherCommandLine(L"C:\\svc\\SG_PersistantService.exe").c_str());
        }

        TEST_METHOD(BuildHostCommandLineQuotesPathAndArgs)
        {
            Assert::AreEqual(L"\"C:\\Apps\\SampleApp.exe\" \"\"",
                BuildHostCommandLine(L"C:\\Apps\\SampleApp.exe", L"").c_str());
            Assert::AreEqual(L"\"C:\\Apps\\SampleApp.exe\" \"--hidden\"",
                BuildHostCommandLine(L"C:\\Apps\\SampleApp.exe", L"--hidden").c_str());
        }

        TEST_METHOD(GetExePathReturnsDirectoryWithTrailingSlash)
        {
            std::wstring path = GetExePath();
            Assert::IsFalse(path.empty());
            wchar_t last = path.back();
            Assert::IsTrue(last == L'\\' || last == L'/');
            Assert::IsTrue(PathFileExistsW(path.c_str()) != FALSE);
            Assert::AreEqual(L"", ExtractFileName(path).c_str());
        }
    };

    TEST_CLASS(RegistryConfig)
    {
    public:
        TEST_METHOD(RoundTripStringUnderCurrentUser)
        {
            TestKeyGuard guard;
            wchar_t subkey[] = L"Software\\SG_PersistantService_UnitTests";
            wchar_t valueName[] = L"Path";
            wchar_t written[] = L"C:\\Apps\\SampleApp.exe";

            Assert::IsTrue(CreateRegistryKey(HKEY_CURRENT_USER, subkey) != FALSE);
            Assert::IsTrue(writeStringInRegistry(HKEY_CURRENT_USER, subkey, valueName, written) != FALSE);

            std::wstring readBack;
            Assert::IsTrue(readStringFromRegistry(HKEY_CURRENT_USER, subkey, valueName, readBack) != FALSE);
            Assert::AreEqual(written, readBack.c_str());
        }

        TEST_METHOD(GetStringRegKeyStripsSurroundingQuotes)
        {
            TestKeyGuard guard;
            wchar_t subkey[] = L"Software\\SG_PersistantService_UnitTests";
            wchar_t valueName[] = L"Path";
            wchar_t quoted[] = L"\"D:\\Host\\WatchMe.exe\"";

            Assert::IsTrue(CreateRegistryKey(HKEY_CURRENT_USER, subkey) != FALSE);
            Assert::IsTrue(writeStringInRegistry(HKEY_CURRENT_USER, subkey, valueName, quoted) != FALSE);

            HKEY hKey = NULL;
            Assert::AreEqual(ERROR_SUCCESS,
                RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey));

            std::wstring value;
            LONG err = GetStringRegKey(hKey, valueName, value, L"unused-default");
            RegCloseKey(hKey);

            Assert::AreEqual(ERROR_SUCCESS, err);
            Assert::AreEqual(L"D:\\Host\\WatchMe.exe", value.c_str());
        }

        TEST_METHOD(GetStringRegKeyUsesDefaultWhenValueMissing)
        {
            TestKeyGuard guard;
            wchar_t subkey[] = L"Software\\SG_PersistantService_UnitTests";
            Assert::IsTrue(CreateRegistryKey(HKEY_CURRENT_USER, subkey) != FALSE);

            HKEY hKey = NULL;
            Assert::AreEqual(ERROR_SUCCESS,
                RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey));

            std::wstring value;
            LONG err = GetStringRegKey(hKey, L"MissingValue", value, L"fallback-path.exe");
            RegCloseKey(hKey);

            Assert::AreNotEqual(ERROR_SUCCESS, err);
            Assert::AreEqual(L"fallback-path.exe", value.c_str());
        }

        TEST_METHOD(ReadMissingKeyLeavesBufferAndFails)
        {
            std::wstring readData = L"sentinel";
            wchar_t missing[] = L"Software\\SG_PersistantService_UnitTests_NoSuchKey";
            wchar_t valueName[] = L"Path";
            Assert::IsFalse(readStringFromRegistry(HKEY_CURRENT_USER, missing, valueName, readData) != FALSE);
            Assert::AreEqual(L"sentinel", readData.c_str());
        }

        TEST_METHOD(WriteToMissingKeyFails)
        {
            wchar_t missing[] = L"Software\\SG_PersistantService_UnitTests_NoSuchKey";
            wchar_t valueName[] = L"Path";
            wchar_t data[] = L"C:\\x.exe";
            Assert::IsFalse(writeStringInRegistry(HKEY_CURRENT_USER, missing, valueName, data) != FALSE);
        }

        TEST_METHOD(CreateRegistryKeyRejectsNullParent)
        {
            wchar_t subkey[] = L"Software\\SG_PersistantService_UnitTests";
            Assert::IsFalse(CreateRegistryKey(NULL, subkey) != FALSE);
        }
    };

    TEST_CLASS(ServiceStatusReporting)
    {
    public:
        TEST_METHOD_INITIALIZE(ResetStatus)
        {
            ZeroMemory(&serviceStatus, sizeof(serviceStatus));
            hServiceStatus = NULL;
        }

        TEST_METHOD(StartPendingAcceptsNoControls)
        {
            ReportServiceStatus(SERVICE_START_PENDING, ERROR_BUSY, 1500);
            Assert::AreEqual<DWORD>(SERVICE_START_PENDING, serviceStatus.dwCurrentState);
            Assert::AreEqual<DWORD>(ERROR_BUSY, serviceStatus.dwWin32ExitCode);
            Assert::AreEqual<DWORD>(1500, serviceStatus.dwWaitHint);
            Assert::AreEqual<DWORD>(0, serviceStatus.dwControlsAccepted);
            Assert::AreNotEqual<DWORD>(0, serviceStatus.dwCheckPoint);
        }

        TEST_METHOD(RunningAcceptsStopAndSessionChange)
        {
            ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
            Assert::AreEqual<DWORD>(SERVICE_RUNNING, serviceStatus.dwCurrentState);
            Assert::AreEqual<DWORD>(NO_ERROR, serviceStatus.dwWin32ExitCode);
            const DWORD accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
            Assert::AreEqual<DWORD>(accepted, serviceStatus.dwControlsAccepted);
            Assert::AreEqual<DWORD>(0, serviceStatus.dwCheckPoint);
        }

        TEST_METHOD(StoppedClearsCheckPoint)
        {
            ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
            Assert::AreEqual<DWORD>(SERVICE_STOPPED, serviceStatus.dwCurrentState);
            Assert::AreEqual<DWORD>(0, serviceStatus.dwCheckPoint);
        }
    };

    TEST_CLASS(ControlHandler)
    {
    public:
        TEST_METHOD_INITIALIZE(ResetHandlerState)
        {
            ZeroMemory(&serviceStatus, sizeof(serviceStatus));
            hServiceStatus = NULL;
            ghSvcStopEvent = NULL;
            hPrevAppProcess = NULL;
            g_bLoggedIn = false;
        }

        TEST_METHOD_CLEANUP(CloseStopEvent)
        {
            if (ghSvcStopEvent)
            {
                CloseHandle(ghSvcStopEvent);
                ghSvcStopEvent = NULL;
            }
        }

        TEST_METHOD(StopSignalsServiceStopEvent)
        {
            ghSvcStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            Assert::IsNotNull(ghSvcStopEvent);

            DWORD result = CtrlHandlerEx(SERVICE_CONTROL_STOP, 0, NULL, NULL);
            Assert::AreEqual<DWORD>(NO_ERROR, result);
            Assert::AreEqual<DWORD>(WAIT_OBJECT_0, WaitForSingleObject(ghSvcStopEvent, 0));
            Assert::AreEqual<DWORD>(SERVICE_STOP_PENDING, serviceStatus.dwCurrentState);
        }

        TEST_METHOD(ShutdownAlsoSignalsStopEvent)
        {
            ghSvcStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            Assert::IsNotNull(ghSvcStopEvent);

            DWORD result = CtrlHandlerEx(SERVICE_CONTROL_SHUTDOWN, 0, NULL, NULL);
            Assert::AreEqual<DWORD>(NO_ERROR, result);
            Assert::AreEqual<DWORD>(WAIT_OBJECT_0, WaitForSingleObject(ghSvcStopEvent, 0));
        }

        TEST_METHOD(UnknownControlIsNotImplemented)
        {
            DWORD result = CtrlHandlerEx(0x00FFFFFF, 0, NULL, NULL);
            Assert::AreEqual<DWORD>(ERROR_CALL_NOT_IMPLEMENTED, result);
        }

        TEST_METHOD(PauseAndInterrogateReturnSuccess)
        {
            Assert::AreEqual<DWORD>(NO_ERROR, CtrlHandlerEx(SERVICE_CONTROL_PAUSE, 0, NULL, NULL));
            Assert::AreEqual<DWORD>(NO_ERROR, CtrlHandlerEx(SERVICE_CONTROL_INTERROGATE, 0, NULL, NULL));
        }

        TEST_METHOD(SessionLogoffClearsPreviousAppProcess)
        {
            hPrevAppProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1234));
            DWORD result = CtrlHandlerEx(SERVICE_CONTROL_SESSIONCHANGE, WTS_SESSION_LOGOFF, NULL, NULL);
            Assert::AreEqual<DWORD>(NO_ERROR, result);
            Assert::IsNull(hPrevAppProcess);
        }
    };

    TEST_CLASS(WatchdogAndHost)
    {
    public:
        TEST_METHOD(GetServiceProcessIdNullHandleIsZero)
        {
            Assert::AreEqual<DWORD>(0, GetServiceProcessID(NULL));
        }

        TEST_METHOD(RunHostRejectsMissingExecutable)
        {
            wchar_t missing[] = L"C:\\SG_PersistantService_no_such_host_918273.exe";
            wchar_t args[] = L"";
            Assert::IsFalse(RunHost(missing, args) != FALSE);
        }

        TEST_METHOD(LogoffMessageClearsLoggedInFlag)
        {
            g_bLoggedIn = true;
            LRESULT result = S_WndProc(NULL, WM_ENDSESSION, 0, 0);
            Assert::AreEqual((LRESULT)0, result);
            Assert::IsFalse(g_bLoggedIn);
        }

        TEST_METHOD(QueryEndSessionAlsoClearsLoggedInFlag)
        {
            g_bLoggedIn = true;
            LRESULT result = S_WndProc(NULL, WM_QUERYENDSESSION, 0, 0);
            Assert::AreEqual((LRESULT)0, result);
            Assert::IsFalse(g_bLoggedIn);
        }

        TEST_METHOD(GetLoggedInUserMatchesSessionWhenPresent)
        {
            std::wstring user = GetLoggedInUser();
            if (!user.empty())
            {
                wchar_t name[UNLEN + 1] = {};
                DWORD n = UNLEN + 1;
                Assert::IsTrue(GetUserNameW(name, &n) != FALSE);
                Assert::AreEqual(name, user.c_str());
            }
        }
    };
}
// clang-format on
