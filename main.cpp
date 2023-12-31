#include "main.h"

void ThreadStart()
{
	char* StartRule = new char[MAX_PATH];
	char* FinalRule = new char[MAX_PATH];

	StartRule = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "StartRule");
	FinalRule = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "FinalRule");

	for (;;)
	{
		bool bESC = true;
		static bool bStatus = false;
		static bool bInit = true;

		if (bInit)
		{
			CleanUp();
			FirewallBlockIN();
			bInit = false;
		}

		if (GetAsyncKeyState(VK_ESCAPE) && bESC)
		{
			bESC = false;
		}

		if (bESC)
		{
			if (checkInternetConnection())
			{
				if (bStatus)
				{
					if (bLanguageOS())
					{
						SetConsoleTitle("В сети");
					}
					else
					{
						SetConsoleTitle("Online");
					}

					bStatus = false;
				}

				if (isFirewallRule("TCP", 2))
				{
					system("netsh advfirewall firewall delete rule dir=out name=TCP > nul");
				}
				else
				{
					static bool bTCP = false;

					if (bTCP)
					{
						TCP(FinalRule);
						bTCP = false;
					}
					else
					{
						TCP(StartRule);
						bTCP = true;
					}
				}

				if (isFirewallRule("UDP", 2))
				{
					system("netsh advfirewall firewall delete rule dir=out name=UDP > nul");
				}
				else
				{
					static bool bUDP = false;

					if (bUDP)
					{
						UDP(FinalRule);
						bUDP = false;
					}
					else
					{
						UDP(StartRule);
						bUDP = true;
					}
				}
			}
			else
			{
				if (!bStatus)
				{
					if (bLanguageOS())
					{
						SetConsoleTitle("Не в сети");
					}
					else
					{
						SetConsoleTitle("Offline");
					}

					bStatus = true;
				}
			}
		}
		else
		{
			system("cls");
			CleanUp();
			CleanLogs();
			printf("\n");
			system("pause");
			KillEXE(HackExeName().c_str());
		}

		if (!isFirewall())
		{
			StateON();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}

void ThreadEnd()
{
	char* iniSystem = new char[MAX_PATH];
	iniSystem = IniRead(szDirHack("Settings.ini").c_str(), "Settings", "Type");
	int iniType = atoi(iniSystem);

	if (iniType == 1)
	{
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathAnyWay("").c_str(), NULL, NULL);
	}

	if (iniType == 2)
	{
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathToUSB("").c_str(), NULL, NULL);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathToFull().c_str(), NULL, NULL);
	}

	if (iniType == 3)
	{
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathAnyWay("").c_str(), NULL, NULL);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathToUSB("").c_str(), NULL, NULL);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MonitorDirectory, (LPVOID)GetPathToFull().c_str(), NULL, NULL);
	}

	if (iniType != 0)
	{
		for(;;)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}
}

int main()
{
	if (strstr(HackExeName().c_str(), "HICE.exe"))
	{
		setlocale(LC_ALL, "Russian");

		SetConsoleCP(1251);
		SetConsoleOutputCP(1251);

		std::thread thread_part1(ThreadStart);
		std::thread thread_part2(ThreadEnd);

		for(;;)
		{
			if (thread_part1.joinable())
			{
				thread_part1.join();
			}

			if (thread_part2.joinable())
			{
				thread_part2.join();
			}
		}
	}
	else
	{
		rename(_EXE().c_str(), szDirHack("HICE.exe").c_str());
	}

	return 0;
}



