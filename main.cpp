
#include "windows.h"
#include <tlhelp32.h>

#include <process.h>
#include <string>
#include <iostream>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>

using namespace std;


void* lpBuffer = operator new[](0x800000u);

const wchar_t* wcL = L"<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>ClientStart</OpC><P></P></M>";
const wchar_t* wcL2 = L"<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>CheckEnv</OpC><P></P></M>";

void killProcessByName(const wchar_t* filename)
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (wcscmp(pEntry.szExeFile, filename) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}

#define BUF_SIZE 4096
// 定义管道名 , 如果是跨网络通信 , 则在圆点处指定服务器端程序所在的主机名
#define EXAMP_PIPE   L"\\\\.\\pipe\\ESurfingClientPipe"

void __fastcall DoStartSvc();

const wchar_t* sub_key = L"SOFTWARE\\Wow6432Node\\ctc_ESurfing";

bool SetValue(const std::string& key, const std::string& value) {
    HKEY hkey = nullptr;
    LSTATUS res = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_key, 0, KEY_WRITE, &hkey);
    if (res != ERROR_SUCCESS) {
        res = ::RegCreateKeyW(HKEY_LOCAL_MACHINE, sub_key, &hkey);
    }
    if (res != ERROR_SUCCESS) {
        return false;
    }
    std::shared_ptr<void> close_key(nullptr, [&](void*) {
        if (hkey != nullptr) {
            ::RegCloseKey(hkey);
            hkey = nullptr;
        }
        });
    res = ::RegSetValueExA(hkey, key.c_str(), 0, REG_SZ, (BYTE*)value.c_str(), value.length());
    if (res != ERROR_SUCCESS) {
        return false;
    }
    return true;
}


std::string GetValue(const std::string& key) {
    HKEY hkey = nullptr;
    LSTATUS res = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_key, 0, KEY_READ, &hkey);
    if (res != ERROR_SUCCESS) {
        return "";
    }
    std::shared_ptr<void> close_key(nullptr, [&](void*) {
        if (hkey != nullptr) {
            ::RegCloseKey(hkey);
            hkey = nullptr;
        }
        });
    DWORD type = REG_SZ;
    DWORD size = 0;
    res = ::RegQueryValueExA(hkey, key.c_str(), 0, &type, nullptr, &size);
    if (res != ERROR_SUCCESS || size <= 0) {
        return "";
    }
    std::vector<BYTE> value_data(size);
    res = ::RegQueryValueExA(hkey, key.c_str(), 0, &type, value_data.data(), &size);
    if (res != ERROR_SUCCESS) {
        return "";
    }
    return std::string(value_data.begin(), value_data.end());
}



int main()
{
    memset(lpBuffer, 0, 0x800000u);

    do {
        killProcessByName(L"ESurfingSvr.exe");

        Sleep(750L);

        killProcessByName(L"ESurfingSvr.exe");

        Sleep(750L);

        static std::random_device rd;
        static std::uniform_int_distribution<uint64_t> dist(0ULL, 0xFFFFFFFFFFFFFFFFULL);
        uint64_t ab = dist(rd);
        uint64_t cd = dist(rd);
        uint32_t a, b, c, d;
        std::stringstream ss;
        ab = (ab & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
        cd = (cd & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
        a = (ab >> 32U);
        b = (ab & 0xFFFFFFFFU);
        c = (cd >> 32U);
        d = (cd & 0xFFFFFFFFU);
        ss << std::hex << std::nouppercase << std::setfill('0');
        ss << std::setw(8) << (a) << '-';
        ss << std::setw(4) << (b >> 16U) << '-';
        ss << std::setw(4) << (b & 0xFFFFU) << '-';
        ss << std::setw(4) << (c >> 16U) << '-';
        ss << std::setw(4) << (c & 0xFFFFU);
        ss << std::setw(8) << d;

        // 通过修改 clientId 的方式挤掉 同一个验证服务器的上一个 session 实现无限续杯不掉线 (需要搭配espatch 将验证服务器锁定为同一个地址)
        
        cout << "gen : " << ss.str() << endl;

        cout << "old : " << GetValue("clientId") << endl;

        cout << "set : " << SetValue("clientId", ss.str()) << endl;

        cout << "new : " << GetValue("clientId") << endl;

        DoStartSvc();

        Sleep(750L);

        void doo();

        doo();

        Sleep(750L);
    } while (true);

    system("pause");

    return 0;
}


void doo() {
    HANDLE hPipe = NULL;

    // 判断是否有可以利用的命名管道  
    if (!WaitNamedPipe(EXAMP_PIPE, NMPWAIT_USE_DEFAULT_WAIT))
    {
        cout << "No Read Pipe Accessible" << endl;
        return;
    }

    // 打开可用的命名管道 , 并与服务器端进程进行通信  
    hPipe = CreateFile(EXAMP_PIPE, GENERIC_READ | GENERIC_WRITE,
        0,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        cout << "Open Read Pipe Error" << endl;

        CloseHandle(hPipe);

        return;
    }

    DWORD  cbRead;
    BOOL   fSuccess = FALSE;

    wstring account = L"123456";
    wstring password = L"7890";

    ///*  cout << "输入账号:\n";
    //  wcin >> account;
    //  cout << endl;
    //  wcout << "账号: " << account << L"\n";

    //  cout << "输入密码:\n";
    //  wcin >> password;
    //  cout << endl;
    //  wcout << "密码: " << password << L"\n";*/



    wstring wcL3 = L"<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>PortalConnect</OpC><P><user>" + account + L"</user><password>" + password + L"</password></P></M>";
    const wchar_t* wcL3_ = wcL3.c_str();

    wcout << wcL3_ << endl;

    //   system("pause");


       //DIS_REASON_STARTUP: "5",        //5：客户端启动自动下线（上次退出未正常下线）；
    const wchar_t* Discon = L"<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>PortalDisConnect</OpC><P><src>5</src></P></M>";

    /*
var CLIENT_START ='ClientStart'  //客户端启动
var CLIENT_START_COMPLETE='ClientStartComplete' //服务启动完成
var SERVER_STATUS_RESP ='ServerStatusResp' //服务状态    ESERVERSTATUS
var CHECK_ENV ='CheckEnv' //检测网络环境
var CHECK_ENV_RESP ='CheckEnvResp' //返回网络环境状态
var GET_NETINFO_RESP ='GetNetInfoResp' //返回网络信息
var PORTAL_CONNECT ='PortalConnect' //请求连接
var PORTAL_CONNECT_RESP ='PortalConnectResp' //连接请求返回
var PORTAL_DISCONNECT ='PortalDisConnect' //请求断开连接
var PORTAL_DISCONNECT_RESP ='PortalDisconnectResp' //断开连接返回
var APP_ERR ='AppErr'  //程序出错
var CHECK_WIFI_RESP ='CheckWifiResp' //Wifi共享软件检测结果

var NET_STATE_MESSAGE_RESP ='NetStateMessageResp' //拨号消息
var NET_STATE_MESSAGE_RESP_EX ='NetStateMessageRespEx' //拨号消息
var TICKET_RESP ='TicketResp'    //返回ticket

var SET_VALUE ='SetValue' //设置数据
var GET_VALUE ='GetValue' //获取数据
var FUN_CFG =	"FunCfg"  //功能配置

var LOG_TRACE ='Log' //日志跟踪
var LOG_CHECK_WIFI_POST ='LogCheckWifiPost' //检测到共享软件后错误上报

var TERMINAL_REQUEST ='GetTerminalData' //请求终端信息
var TERMINAL_RESP ='SetTerminalData' //终端信息返回
var TERMINAL_TERM_REQUEST ='TerminalTermSend' //上网终端界面请求其他设备下线
var TERMINAL_TERM_RESP ='TerminalTermReturn' //上网终端界面请求其他设备下线返回

var CHECK_SYSTEM_TIME ='CheckSystemTime' //系统时间检测

var DATA_SUBMIT = 'DataSubmit' //错误上报
var DISASTER_URL = 'DisasterUrl' //打开应急页面

var UPDATE_COMPLETE = 'UpdateComplete';

    */

    //通信方式为半双工 需要确认 完全收完了消息才能写


   // The pipe connected; change to message-read mode. 


    DWORD dwWritten;

    WriteFile(hPipe,
        wcL,
        2 * wcslen(wcL),
        &dwWritten,
        NULL);

    DWORD NumberOfBytesRead = 0;

    wcout << "write" << endl;

    do {


        fSuccess = ReadFile(
            hPipe,    // pipe handle 
            lpBuffer,    // buffer to receive reply 
            0x800000u,  // size of buffer 
            &cbRead,  // number of bytes read 
            NULL);    // not overlapped 

        if (!fSuccess || wcslen(static_cast<wchar_t*>(lpBuffer)) <= 0)
        {
            cout << "ReadFile from pipe failed. \n";

            CloseHandle(hPipe);

            return;
        }


        wcout << static_cast<wchar_t*>(lpBuffer) << endl;
    } while (!wcsstr(static_cast<wchar_t*>(lpBuffer), L"ClientStartComplete"));

    cout << "初始化完毕， IP 更换后需要在这里开始执行一次" << endl << endl << endl << endl;
    //修改Hook的地方直接改IP 好像更方便一点

    WriteFile(hPipe,
        wcL2,
        2 * wcslen(wcL2),
        &dwWritten,
        NULL);

    int i = 0;
    do {
        fSuccess = ReadFile(
            hPipe,    // pipe handle 
            lpBuffer,    // buffer to receive reply 
            0x800000u,  // size of buffer 
            &cbRead,  // number of bytes read 
            NULL);    // not overlapped 

        if (!fSuccess || wcslen(static_cast<wchar_t*>(lpBuffer)) <= 0)
        {
            if (++i > 50) {
                cout << "ReadFile from pipe failed. \n";


                CloseHandle(hPipe);

                return;
            }
        }

        wcout << static_cast<wchar_t*>(lpBuffer) << endl;


        if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<newState>2</newState>")) {
            cout << "已经连网了, 正在退出...." << endl << endl << endl << endl;

            //     WriteFile(hPipe,
             //        Discon,
            //         2 * wcslen(Discon),
            //         &dwWritten,
           //          NULL);

                 // 这里好像退出不了 原因未知 只能重启服务然后挤掉线
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>30000105</ErrorCode>")) {

            //code.js '30000105': '重新获取用户标识'

            WriteFile(hPipe,
                wcL2,
                2 * wcslen(wcL2),
                &dwWritten,
                NULL);


        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<newState>32</newState><ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;


            /*          WriteFile(hPipe,
                           wcL2,
                           2 * wcslen(wcL2),
                           &dwWritten,
                           NULL);

                           */

            CloseHandle(hPipe);

            return;
        }
    } while (!wcsstr(static_cast<wchar_t*>(lpBuffer), L"TicketResp"));




    cout << "登录中" << endl << endl << endl << endl;
    WriteFile(hPipe,
        wcL3_,
        2 * wcslen(wcL3_),
        &dwWritten,
        NULL);

    //check globalDefine.js   ET_PORTAL -> 51 
    //<oldState>1</oldState><newState>2</newState> -> ES_CONNECTED

    i = 0;
    do {
        fSuccess = ReadFile(
            hPipe,    // pipe handle 
            lpBuffer,    // buffer to receive reply 
            0x800000u,  // size of buffer 
            &cbRead,  // number of bytes read 
            NULL);    // not overlapped 

        if (!fSuccess || wcslen(static_cast<wchar_t*>(lpBuffer)) <= 0)
        {
            if (++i > 50) {
                cout << "ReadFile from pipe failed. \n";


                break;
            }
        }

        srand(time(NULL));

        wcout << static_cast<wchar_t*>(lpBuffer) << L"  " << wcslen(static_cast<wchar_t*>(lpBuffer)) << endl;

        if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<newState>2</newState>")) {
            cout << "登录成功!" << endl << endl << endl << endl;

            Sleep(60 * (17 + rand() % 4) * 1000);

            break;


        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"TicketResp")) { //好像要多来几次
            cout << "登录中" << endl << endl << endl << endl;
            WriteFile(hPipe,
                wcL3_,
                2 * wcslen(wcL3_),
                &dwWritten,
                NULL);

            Sleep(2 * 1000);
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>150009</ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);

            CloseHandle(hPipe);

            return;
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>20010207</ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);

            CloseHandle(hPipe);

            return;
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>20010204</ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);

            CloseHandle(hPipe);

            return;
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>20010205</ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);


            CloseHandle(hPipe);


            return;
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<ErrorCode>150107</ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);

            CloseHandle(hPipe);

            return;
        }
        else if (wcsstr(static_cast<wchar_t*>(lpBuffer), L"<newState>32</newState><ErrorCode>")) { //HTTP ERROR 500
            cout << "重新获取ing" << endl << endl << endl << endl;
            /*        WriteFile(hPipe,
                        wcL2,
                        2 * wcslen(wcL2),
                        &dwWritten,
                        NULL);

                    */


            Sleep(2 * 1000);


            CloseHandle(hPipe);


            return;
        }

    } while (true);

    //没登录成功可以重新开一次试试 (Ticket过期)



    cout << "退出!" << endl << endl << endl << endl;
    CloseHandle(hPipe);

}

/**
 *  https://docs.microsoft.com/en-us/windows/win32/services/starting-a-service
*/

VOID __fastcall DoStartSvc()
{
    SERVICE_STATUS_PROCESS ssStatus;
    ULONGLONG dwOldCheckPoint;
    ULONGLONG dwStartTickCount;
    ULONGLONG dwWaitTime;
    DWORD dwBytesNeeded;

    // Get a handle to the SCM database. 

    SC_HANDLE schSCManager = OpenSCManager(
        NULL,                    // local computer
        NULL,                    // servicesActive database 
        SC_MANAGER_ALL_ACCESS);  // full access rights 

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    SC_HANDLE schService = OpenServiceW(
        schSCManager,         // SCM database 
        L"ESurfingSvr",            // name of service 
        SERVICE_ALL_ACCESS);  // full access 

    if (schService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Check the status in case the service is not stopped. 

    if (!QueryServiceStatusEx(
        schService,                     // handle to service 
        SC_STATUS_PROCESS_INFO,         // information level
        (LPBYTE)&ssStatus,             // address of structure
        sizeof(SERVICE_STATUS_PROCESS), // size of structure
        &dwBytesNeeded))              // size needed if buffer is too small
    {
        printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Check if the service is already running. It would be possible 
    // to stop the service here, but for simplicity this example just returns. 

    if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
    {
        //        printf("Cannot start the service because it is already running\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Save the tick count and initial checkpoint.

    dwStartTickCount = GetTickCount64();
    dwOldCheckPoint = ssStatus.dwCheckPoint;

    // Wait for the service to stop before attempting to start it.

    while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
    {
        // Do not wait longer than the wait hint. A good interval is 
        // one-tenth of the wait hint but not less than 1 second  
        // and not more than 10 seconds. 

        dwWaitTime = ssStatus.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        // Check the status until the service is no longer stop pending. 

        if (!QueryServiceStatusEx(
            schService,                     // handle to service 
            SC_STATUS_PROCESS_INFO,         // information level
            (LPBYTE)&ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded))              // size needed if buffer is too small
        {
            printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return;
        }

        if (ssStatus.dwCheckPoint > dwOldCheckPoint)
        {
            // Continue to wait and check.

            dwStartTickCount = GetTickCount64();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else
        {
            if (GetTickCount64() - dwStartTickCount > ssStatus.dwWaitHint)
            {
                printf("Timeout waiting for service to stop\n");
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                return;
            }
        }
    }

    // Attempt to start the service.

    if (!StartService(
        schService,  // handle to service 
        0,           // number of arguments 
        NULL))      // no arguments 
    {
        printf("StartService failed (%d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }
    else printf("Service start pending...\n");

    // Check the status until the service is no longer start pending. 

    if (!QueryServiceStatusEx(
        schService,                     // handle to service 
        SC_STATUS_PROCESS_INFO,         // info level
        (LPBYTE)&ssStatus,             // address of structure
        sizeof(SERVICE_STATUS_PROCESS), // size of structure
        &dwBytesNeeded))              // if buffer too small
    {
        printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Save the tick count and initial checkpoint.

    dwStartTickCount = GetTickCount64();
    dwOldCheckPoint = ssStatus.dwCheckPoint;

    while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
    {
        // Do not wait longer than the wait hint. A good interval is 
        // one-tenth the wait hint, but no less than 1 second and no 
        // more than 10 seconds. 

        dwWaitTime = ssStatus.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        // Check the status again. 

        if (!QueryServiceStatusEx(
            schService,             // handle to service 
            SC_STATUS_PROCESS_INFO, // info level
            (LPBYTE)&ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded))              // if buffer too small
        {
            printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
            break;
        }

        if (ssStatus.dwCheckPoint > dwOldCheckPoint)
        {
            // Continue to wait and check.

            dwStartTickCount = GetTickCount64();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else
        {
            if (GetTickCount64() - dwStartTickCount > ssStatus.dwWaitHint)
            {
                // No progress made within the wait hint.
                break;
            }
        }
    }

    // Determine whether the service is running.

    if (ssStatus.dwCurrentState == SERVICE_RUNNING)
    {
        printf("Service started successfully.\n");
    }
    else
    {
        printf("Service not started. \n");
        printf("  Current State: %d\n", ssStatus.dwCurrentState);
        printf("  Exit Code: %d\n", ssStatus.dwWin32ExitCode);
        printf("  Check Point: %d\n", ssStatus.dwCheckPoint);
        printf("  Wait Hint: %d\n", ssStatus.dwWaitHint);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}
