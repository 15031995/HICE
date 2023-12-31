#include <Windows.h>
#include <cstdio>
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <algorithm>
#include <Psapi.h>
#include <cstdlib>
#include <tlhelp32.h>
#include <locale>
#include <filesystem>
#include <ctime>
#include <chrono>
#include <stdexcept>
#include <codecvt>
#include <unordered_set>
#include <WtsApi32.h>
#include <unordered_map>
#include <sstream>
#include <Shlwapi.h>
#include <netfw.h>
#include <vector>
#include <atlcomcli.h>
#include <comutil.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <thread>
#include <wlanapi.h>
#include <wininet.h>

#pragma comment(lib,"Wininet.lib")
#pragma comment(lib,"Wlanapi.lib")

#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"wbemuuid.lib")

#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")

#pragma warning(disable:4996)
#pragma warning(disable:4129)

#pragma warning(disable:4101) 
#pragma warning(disable:4018)

using namespace std;
#define INFO_BUFFER_SIZE 1024

template <int XORSTART, int BUFLEN, int XREFKILLER>
class XorStr
{
private:
	XorStr();
public:
	char s[BUFLEN];
	XorStr(const char* xs);
};

template <int XORSTART, int BUFLEN, int XREFKILLER>
XorStr<XORSTART, BUFLEN, XREFKILLER>::XorStr(const char* xs)
{
	int xvalue = XORSTART;
	for (int i = 0; i < (BUFLEN - 1); i++)
	{
		s[i] = xs[i - XREFKILLER] ^ xvalue;
		xvalue += 1;
		xvalue %= 256;
	}
	s[BUFLEN - 1] = 0;
}

inline char* IniRead(const char* filename, const char* section, const char* key)
{
	char* out = new char[MAX_PATH];
	GetPrivateProfileString(
		(LPCSTR)section,
		(LPCSTR)key,
		NULL,
		out,
		MAX_PATH,
		(LPCSTR)filename
	);
	return out;
}

//inline void copyFile(const std::string& sourceFile, const std::string& destinationFile)
//{
//	std::ifstream source(sourceFile, std::ios::binary);
//	std::ofstream dest(destinationFile, std::ios::binary);
//
//	dest << source.rdbuf();
//	source.close();
//
//	dest.close();
//}

inline string HackExeName()
{
	const size_t len = 260;
	LPSTR buffer = new TCHAR[len];
	GetModuleFileName(NULL, buffer, len);
	char* szHackName = PathFindFileName(buffer);
	return szHackName;
}

inline string Username()
{
	TCHAR infoBuf[INFO_BUFFER_SIZE];
	DWORD lpBuffer = INFO_BUFFER_SIZE;

	GetUserName(infoBuf, &lpBuffer);
	return infoBuf;
}

inline string GetPathAnyWay(const char* str)
{
	char buffer[MAX_PATH];
	GetSystemDirectory(buffer, sizeof(buffer));

	string windowsDir(buffer);
	size_t pos = windowsDir.find('\\', 3);
	string diskPath = windowsDir.substr(0, pos - 7);

	char cmd[256];
	sprintf(cmd, "%s", diskPath.c_str());

	return cmd;
}

inline string convertWstringToString(const std::wstring& wstr)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>converter;
	return converter.to_bytes(wstr);
}


inline string GetPathToFull()
{
	DWORD drives = GetLogicalDrives();
	string path;

	for (char i = 'A'; i <= 'Z'; i++)
	{
		if (drives & 1)
		{
			std::wstring drivePath = (std::wstring(1, i) + L":\\");
			path = convertWstringToString(drivePath);
		}
		drives >>= 1;
	}
	return path;
}

inline string GetPathToUSB(const char* str)
{
	char szLogicalDrivers[64];
	char USB[MAX_PATH];

	DWORD dwResult = GetLogicalDriveStringsA(sizeof(szLogicalDrivers), szLogicalDrivers);
	if (dwResult > 0 && dwResult <= sizeof(szLogicalDrivers))
	{
		char* szSingleDriver = szLogicalDrivers;

		while (*szSingleDriver)
		{
			UINT driveType = GetDriveTypeA(szSingleDriver);
			if (driveType == DRIVE_REMOVABLE || driveType == DRIVE_FIXED)
			{

				sprintf(USB, "%s", szSingleDriver);
				str = USB;
			}
			szSingleDriver += strlen(szSingleDriver) + 1;
		}
	}
	return str;
}

inline string szDirHack(const char* szName)
{
	TCHAR buffer[MAX_PATH];
	GetCurrentDirectory(sizeof(buffer), buffer);
	char str[MAX_PATH];
	sprintf(str, "%s\\", buffer);
	string pDir = str;
	return (pDir + szName);
}

inline string _EXE()
{
	const size_t len = MAX_PATH;
	LPSTR buffer = new TCHAR[len];
	GetModuleFileName(GetModuleHandle(NULL), buffer, len);
	return buffer;
}

inline DWORD FindProcessByName(const char* procname)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

	pe.dwSize = sizeof(PROCESSENTRY32);

	hResult = Process32First(hSnapshot, &pe);

	while (hResult) {
		if (strcmp(procname, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return pid;
}

inline void dxConsoleColor(int color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

inline bool isRecycle(const std::wstring& filename)
{
	return (filename.find(L"$Recycle.Bin") != std::wstring::npos);
}

inline void MonitorDirectory(char* Path)
{
	DWORD dwBytes;
	char buffer[MAX_PACKAGE_NAME];

	HANDLE hDir = CreateFile(
		Path,
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL
	);

	if (hDir == INVALID_HANDLE_VALUE) {
		return;
	}

	while (true) {
		ReadDirectoryChangesW(
			hDir,
			buffer,
			MAX_PACKAGE_NAME,
			TRUE,
			FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
			&dwBytes,
			NULL,
			NULL
		);

		FILE_NOTIFY_INFORMATION* pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);

		while (pNotify)
		{
			std::wifstream file(szDirHack("HICE.txt").c_str());
			std::vector<std::wstring> forbiddenExtensions;

			file.imbue(std::locale(file.getloc(), new std::codecvt_utf8_utf16<wchar_t>));
			std::wstring pFile(pNotify->FileName, pNotify->FileName + pNotify->FileNameLength / 2);

			if (pNotify->Action == FILE_ACTION_ADDED)
			{
				bool bFile = false;
				char PC[MAX_PATH];

				sprintf(PC, "%s.txt", Username().c_str());
				FILE* pfile = fopen(szDirHack(PC).c_str(), "a+");

				std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
				std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

				char* Time = std::ctime(&currentTime);
				char TXT[MAX_PATH];

				std::wstring wideFileName(pFile);
				std::wstring::size_type pos = wideFileName.find_last_of(L"\\");

				if (pos != std::wstring::npos)
				{
					wideFileName = wideFileName.substr(pos + 1);
				}

				if (file.is_open())
				{
					std::wstring ext;

					while (file >> ext)
					{
						forbiddenExtensions.push_back(ext);
					}

					file.close();
				}

				for (const auto& extension : forbiddenExtensions)
				{
					if (wideFileName.find(extension) != std::wstring::npos)
					{
						char* BlockList = new char[MAX_PATH];
						BlockList = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "BlockList");
						int bType = atoi(BlockList);

						if (bType == 1)
						{
							dxConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
							printf("%s%ls\n", Path, pFile.c_str());
							dxConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
						}

						bFile = true;
					}
				}

				if (!isRecycle(pFile))
				{
					if (!bFile)
					{
						sprintf(TXT, "%s%ls ---> %s", Path, pFile.c_str(), Time);
						printf("%s%ls\n", Path, pFile.c_str());

						if (pfile)
						{
							fputs(TXT, pfile);
							fclose(pfile);
						}

						bFile = false;
					}
				}
			}

			if (pNotify->NextEntryOffset == 0) {
				break;
			}

			char* pcNext = reinterpret_cast<char*>(pNotify);
			pcNext += pNotify->NextEntryOffset;
			pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(pcNext);
		}
	}

	CloseHandle(hDir);
}

inline void KillEXE(const char* EXE)
{
	DWORD pID = FindProcessByName(EXE);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);

	if( pID != NULL)
	{ 
		TerminateProcess(hProc, TRUE);
	}

	CloseHandle(hProc);
}

inline void FirewallBlockIN()
{
	system("netsh advfirewall firewall add rule dir=in action=block protocol=TCP localport=1-79,81-442,444-65535 name=TCP > nul");
	system("netsh advfirewall firewall add rule dir=in action=block protocol=UDP localport=1-79,81-442,444-65535 name=UDP > nul");

	system("netsh advfirewall firewall add rule name=ICA dir=in action=block protocol=icmpv4:8,any > nul");
	system("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound > nul");
}

inline void TCP(const char* Rule)
{
	char* PortList = new char[MAX_PATH];
	char cmd[MAX_PATH];

	PortList = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "PortList");
	sprintf(cmd, "netsh advfirewall firewall add rule dir=out action=%s protocol=TCP localport=%s name=TCP > nul", Rule, PortList);

	system(cmd);
}

inline void UDP(const char* Rule)
{
	char* PortList = new char[MAX_PATH];
	char cmd[MAX_PATH];

	PortList = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "PortList");
	sprintf(cmd, "netsh advfirewall firewall add rule dir=out action=%s protocol=UDP localport=%s name=UDP > nul", Rule, PortList);

	system(cmd);
}

inline void StateON()
{
	system("netsh advfirewall set allprofiles state on > nul");
}

inline void CleanUp()
{
	system("netsh advfirewall firewall delete rule name=all > nul");
}

inline BSTR ConvertToBSTR(const char* input)
{
	int length = MultiByteToWideChar(CP_ACP, 0, input, -1, NULL, 0);

	WCHAR* wstr = new WCHAR[length];
	MultiByteToWideChar(CP_ACP, 0, input, -1, wstr, length);

	BSTR bstr = SysAllocString(wstr);
	delete[] wstr;

	return bstr;
}

inline bool isFirewallRule(const char* ruleName, int dir)
{
	HRESULT hr = S_OK;
	bool bStatus = false;
	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	INetFwPolicy2* pNetFwPolicy2 = NULL;
	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);

	if (FAILED(hr))
	{
		CoUninitialize();
	}

	INetFwRules* pFwRules = NULL;
	hr = pNetFwPolicy2->get_Rules(&pFwRules);
	pNetFwPolicy2->Release();

	if (FAILED(hr))
	{
		CoUninitialize();
	}

	IEnumVARIANT* pEnum = NULL;
	hr = pFwRules->get__NewEnum(reinterpret_cast<IUnknown**>(&pEnum));

	if (FAILED(hr))
	{
		pFwRules->Release();
		CoUninitialize();
	}

	VARIANT var;
	ULONG cFetched;

	NET_FW_RULE_DIRECTION ruleDirection;

	while ((hr = pEnum->Next(1, &var, &cFetched)) == S_OK)
	{
		INetFwRule* pFwRule = NULL;

		if (V_DISPATCH(&var))
		{
			hr = V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);

			if (SUCCEEDED(hr) && pFwRule)
			{
				pFwRule->get_Direction(&ruleDirection);

				switch (dir)
				{
				case 1:
					if (ruleDirection == NET_FW_RULE_DIR_IN)
					{
						BSTR RULE = ConvertToBSTR(ruleName);
						hr = pFwRule->get_Name(&RULE);

						if (SUCCEEDED(hr))
						{
							bStatus = true;
						}
						else
						{
							bStatus = false;
						}
						pFwRule->Release();
					}
					break;

				case 2:
					if (ruleDirection == NET_FW_RULE_DIR_OUT)
					{
						BSTR RULE = ConvertToBSTR(ruleName);
						hr = pFwRule->get_Name(&RULE);

						if (SUCCEEDED(hr))
						{
							bStatus = true;
						}
						else
						{
							bStatus = false;
						}
						pFwRule->Release();
					}
					break;

				default:
					break;

				}
			}
		}
		VariantClear(&var);
	}

	pEnum->Release();
	pFwRules->Release();
	CoUninitialize();

	return bStatus;
}

inline bool isFirewall()
{
	HRESULT hr = CoInitialize(NULL);
	bool bStatus = false;

	INetFwMgr* pFwMgr = NULL;
	INetFwPolicy* pFwPolicy = NULL;
	INetFwProfile* pFwProfile = NULL;

	VARIANT_BOOL fwEnabled;
	INetFwRemoteAdminSettings* fwRDP = NULL;

	hr = CoCreateInstance(__uuidof(NetFwMgr),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwMgr),
		(void**)&pFwMgr);

	if (FAILED(hr))
	{
		CoUninitialize();
	}

	hr = pFwMgr->get_LocalPolicy(&pFwPolicy);
	pFwMgr->Release();

	if (FAILED(hr))
	{
		CoUninitialize();
	}

	hr = pFwPolicy->get_CurrentProfile(&pFwProfile);
	pFwPolicy->Release();

	if (FAILED(hr))
	{
		CoUninitialize();
	}

	hr = pFwProfile->get_FirewallEnabled(&fwEnabled);
	pFwProfile->Release();


	if (FAILED(hr))
	{
		CoUninitialize();
	}

	if (fwEnabled)
	{
		bStatus = true;
	}
	else
	{
		bStatus = false;
	}

	CoUninitialize();

	return bStatus;
}

inline bool bLanguageOS()
{
	LANGID langId = GetUserDefaultUILanguage();
	WORD   LanguageId = PRIMARYLANGID(langId);

	if (LanguageId == LANG_RUSSIAN)
	{
		return true;
	}

	if (LanguageId == LANG_ENGLISH)
	{
		return false;
	}

	return false;
}

inline bool checkInternetConnection()
{
	DWORD dwFlags;
	if (InternetGetConnectedState(&dwFlags, 0))
	{
		if ((dwFlags & INTERNET_CONNECTION_MODEM) ||
			(dwFlags & INTERNET_CONNECTION_LAN)   ||
			(dwFlags & INTERNET_CONNECTION_PROXY))
		{
			return true;
		}
	}
	return false;
}

inline void CleanLogs()
{
	system("wevtutil cl Setup");
	system("wevtutil cl System");
	system("wevtutil cl Security");
	system("wevtutil cl Application");
}

