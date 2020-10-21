#ifndef UNICODE
#define UNICODE
#endif

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "NmApi.lib")

#include <winsock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <tcpestats.h>
#include <stdlib.h>
#include <winver.h>
#include <tchar.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <Psapi.h>
#include <list>
#include <algorithm>
#include <string>
#include <cctype>
#include <sstream>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Pdh.h>
#include <iphlpapi.h>

#define _WIN32_DCOM
#define INITGUID
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace std;

static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
static int numProcessors;
static HANDLE hProcess;
static PHANDLE hEngine;

typedef long long int64_t;
typedef unsigned long long uint64_t;

static uint64_t file_time_2_utc(const FILETIME* ftime)
{
	LARGE_INTEGER li;

	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}

static int get_processor_number()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return (int)info.dwNumberOfProcessors;
}

int get_cpu_usage(int pid)
{
	static int processor_count_ = -1;
	static int64_t last_time_ = 0;
	static int64_t last_system_time_ = 0;

	FILETIME now;
	FILETIME creation_time;
	FILETIME exit_time;
	FILETIME kernel_time;
	FILETIME user_time;
	int64_t system_time;
	int64_t time;
	int64_t system_time_delta;
	int64_t time_delta;

	int cpu = -1;

	if (processor_count_ == -1)
	{
		processor_count_ = get_processor_number();
	}

	GetSystemTimeAsFileTime(&now);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!GetProcessTimes(hProcess, &creation_time, &exit_time, &kernel_time, &user_time))
	{
		exit(EXIT_FAILURE);
	}
	system_time = (file_time_2_utc(&kernel_time) + file_time_2_utc(&user_time)) / processor_count_;
	time = file_time_2_utc(&now);

	if ((last_system_time_ == 0) || (last_time_ == 0))
	{
		last_system_time_ = system_time;
		last_time_ = time;
		return get_cpu_usage(pid);
	}

	system_time_delta = system_time - last_system_time_;
	time_delta = time - last_time_;

	if (time_delta == 0)
	{
		return get_cpu_usage(pid);
	}

	cpu = (int)((system_time_delta * 100 + time_delta / 2) / time_delta);
	last_system_time_ = system_time;
	last_time_ = time;
	return cpu;
}

bool findStringIC(const wstring& strHaystack, const wstring& strNeedle)
{
	auto it = search(
		strHaystack.begin(), strHaystack.end(),
		strNeedle.begin(), strNeedle.end(),
		[](char ch1, char ch2) { return toupper(ch1) == toupper(ch2); }
	);
	return (it != strHaystack.end());
}

void init() {
	SYSTEM_INFO sysInfo;
	FILETIME ftime, fsys, fuser;

	GetSystemInfo(&sysInfo);
	numProcessors = sysInfo.dwNumberOfProcessors;

	GetSystemTimeAsFileTime(&ftime);
	memcpy(&lastCPU, &ftime, sizeof(FILETIME));

	GetProcessTimes(hProcess, &ftime, &ftime, &fsys, &fuser);
	memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
	memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
}

int printFileDescriptions(const wchar_t* filename)
{
	int versionInfoSize = GetFileVersionInfoSize(filename, NULL);
	if (!versionInfoSize) {
		return 0;
	}

	auto versionInfo = new BYTE[versionInfoSize];
	std::unique_ptr<BYTE[]> versionInfo_automatic_cleanup(versionInfo);
	if (!GetFileVersionInfo(filename, NULL, versionInfoSize, versionInfo)) {
		return 0;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *translationArray;

	UINT translationArrayByteLength = 0;
	if (!VerQueryValue(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*)&translationArray, &translationArrayByteLength)) {
		return 0;
	}

	for (unsigned int i = 0; i < (translationArrayByteLength / sizeof(LANGANDCODEPAGE)); i++) {
		wchar_t fileDescriptionKey[256];
		wsprintf(
			fileDescriptionKey,
			L"\\StringFileInfo\\%04x%04x\\FileDescription",
			translationArray[i].wLanguage,
			translationArray[i].wCodePage
		);

		wchar_t* fileDescription = NULL;
		UINT fileDescriptionSize;
		if (VerQueryValue(versionInfo, fileDescriptionKey, (LPVOID*)&fileDescription, &fileDescriptionSize)) {
			wcout << fileDescription << endl;
		}
	}

	return TRUE;
}

void GetCpuUsage(DWORD pid)
{
	int cpu;
	
	cpu = get_cpu_usage(pid);
	
	Sleep(500);
	cpu = get_cpu_usage(pid);

	cout << "CPU Usage: " << cpu << '%' << endl;

}

void PrintNetwork()
{
	DWORD dwRetval;
	MIB_IPSTATS* pStats;

	pStats = (MIB_IPSTATS*)MALLOC(sizeof(MIB_IPSTATS));

	if (pStats == NULL) {
		wprintf(L"Unable to allocate memory for MIB_IPSTATS\n");
		exit(1);
	}
	dwRetval = GetIpStatistics(pStats);
	if (dwRetval != NO_ERROR) {
		wprintf(L"GetIpStatistics call failed with %d\n", dwRetval);
		exit(1);
	}
	else {

		wprintf(L"IP forwarding: \t\t");
		switch (pStats->dwForwarding) {
		case MIB_IP_FORWARDING:
			wprintf(L"Enabled\n");
			break;
		case MIB_IP_NOT_FORWARDING:
			wprintf(L"Disabled\n");
			break;
		default:
			wprintf(L"unknown value = %d\n", pStats->dwForwarding);
			break;
		}

		wprintf(L"Default initial TTL: \t\t\t\t\t%u\n", pStats->dwDefaultTTL);

		wprintf(L"Number of received datagrams: \t\t\t\t%u\n", pStats->dwInReceives);
		wprintf(L"Number of received datagrams with header errors: \t%u\n", pStats->dwInHdrErrors);
		wprintf(L"Number of received datagrams with address errors: \t%u\n", pStats->dwInAddrErrors);

		wprintf(L"Number of datagrams forwarded: \t\t\t\t%ld\n", pStats->dwForwDatagrams);

		wprintf(L"Number of received datagrams with an unknown protocol: \t%u\n", pStats->dwInUnknownProtos);
		wprintf(L"Number of received datagrams discarded: \t\t%u\n", pStats->dwInDiscards);
		wprintf(L"Number of received datagrams delivered: \t\t%u\n", pStats->dwInDelivers);

		wprintf(L"Number of outgoing datagrams requested to transmit: \t%u\n", pStats->dwOutRequests);
		wprintf(L"Number of outgoing datagrams discarded for routing: \t%u\n", pStats->dwRoutingDiscards);
		wprintf(L"Number of outgoing datagrams discarded: \t\t%u\n", pStats->dwOutDiscards);
		wprintf(L"Number of outgoing datagrams with no route to destination discarded: %u\n", pStats->dwOutNoRoutes);

		wprintf(L"Fragment reassembly timeout: \t\t\t\t%u\n", pStats->dwReasmTimeout);
		wprintf(L"Number of datagrams that required reassembly: \t\t%u\n", pStats->dwReasmReqds);
		wprintf(L"Number of datagrams successfully reassembled: \t\t%u\n", pStats->dwReasmOks);
		wprintf(L"Number of datagrams that could not be reassembled: \t%u\n", pStats->dwReasmFails);

		wprintf(L"Number of datagrams fragmented successfully: \t\t%u\n", pStats->dwFragOks);
		wprintf(L"Number of datagrams not fragmented and discarded: \t%u\n", pStats->dwFragFails);
		wprintf(L"Number of fragments created: \t\t\t\t%u\n", pStats->dwFragCreates);

		wprintf(L"Number of interfaces: \t\t\t\t\t%u\n", pStats->dwNumIf);
		wprintf(L"Number of IP addresses: \t\t\t\t%u\n", pStats->dwNumAddr);
		wprintf(L"Number of routes: \t\t\t\t\t%u\n", pStats->dwNumRoutes);
	}

	// Free memory allocated for the MIB_IPSTATS structure
	if (pStats)
		FREE(pStats);
}

int PrintIfTable()
{
	// Declare and initialize variables.

	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	unsigned int i, j;

	/* variables used for GetIfTable and GetIfEntry */
	MIB_IFTABLE* pIfTable;
	MIB_IFROW* pIfRow;

	// Allocate memory for our pointers.
	pIfTable = (MIB_IFTABLE*)MALLOC(sizeof(MIB_IFTABLE));
	if (pIfTable == NULL) {
		printf("Error allocating memory needed to call GetIfTable\n");
		return 1;
	}
	// Make an initial call to GetIfTable to get the
	// necessary size into dwSize
	dwSize = sizeof(MIB_IFTABLE);
	if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pIfTable);
		pIfTable = (MIB_IFTABLE*)MALLOC(dwSize);
		if (pIfTable == NULL) {
			printf("Error allocating memory needed to call GetIfTable\n");
			return 1;
		}
	}
	// Make a second call to GetIfTable to get the actual
	// data we want.
	if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) {
		printf("\tNum Entries: %ld\n\n", pIfTable->dwNumEntries);
		for (i = 0; i < pIfTable->dwNumEntries; i++) {
			pIfRow = (MIB_IFROW*)&pIfTable->table[i];
			printf("\tIndex[%d]:\t %ld\n", i, pIfRow->dwIndex);
			printf("\tInterfaceName[%d]:\t %ws", i, pIfRow->wszName);
			printf("\n");
			printf("\tDescription[%d]:\t ", i);
			for (j = 0; j < pIfRow->dwDescrLen; j++)
				printf("%c", pIfRow->bDescr[j]);
			printf("\n");
			printf("\tType[%d]:\t ", i);
			switch (pIfRow->dwType) {
			case IF_TYPE_OTHER:
				printf("Other\n");
				break;
			case IF_TYPE_ETHERNET_CSMACD:
				printf("Ethernet\n");
				break;
			case IF_TYPE_ISO88025_TOKENRING:
				printf("Token Ring\n");
				break;
			case IF_TYPE_PPP:
				printf("PPP\n");
				break;
			case IF_TYPE_SOFTWARE_LOOPBACK:
				printf("Software Lookback\n");
				break;
			case IF_TYPE_ATM:
				printf("ATM\n");
				break;
			case IF_TYPE_IEEE80211:
				printf("IEEE 802.11 Wireless\n");
				break;
			case IF_TYPE_TUNNEL:
				printf("Tunnel type encapsulation\n");
				break;
			case IF_TYPE_IEEE1394:
				printf("IEEE 1394 Firewire\n");
				break;
			default:
				printf("Unknown type %ld\n", pIfRow->dwType);
				break;
			}
			printf("\tMtu[%d]:\t\t %ld\n", i, pIfRow->dwMtu);
			printf("\tSpeed[%d]:\t %ld\n", i, pIfRow->dwSpeed);
			printf("\tPhysical Addr:\t ");
			if (pIfRow->dwPhysAddrLen == 0)
				printf("\n");
			for (j = 0; j < pIfRow->dwPhysAddrLen; j++) {
				if (j == (pIfRow->dwPhysAddrLen - 1))
					printf("%.2X\n", (int)pIfRow->bPhysAddr[j]);
				else
					printf("%.2X-", (int)pIfRow->bPhysAddr[j]);
			}
			printf("\tAdmin Status[%d]:\t %ld\n", i, pIfRow->dwAdminStatus);
			printf("\tOper Status[%d]:\t ", i);
			switch (pIfRow->dwOperStatus) {
			case IF_OPER_STATUS_NON_OPERATIONAL:
				printf("Non Operational\n");
				break;
			case IF_OPER_STATUS_UNREACHABLE:
				printf("Unreachable\n");
				break;
			case IF_OPER_STATUS_DISCONNECTED:
				printf("Disconnected\n");
				break;
			case IF_OPER_STATUS_CONNECTING:
				printf("Connecting\n");
				break;
			case IF_OPER_STATUS_CONNECTED:
				printf("Connected\n");
				break;
			case IF_OPER_STATUS_OPERATIONAL:
				printf("Operational\n");
				break;
			default:
				printf("Unknown status %ld\n", pIfRow->dwAdminStatus);
				break;
			}
			printf("\n");
		}
	}
	else {
		printf("GetIfTable failed with error: \n", dwRetVal);
		if (pIfTable != NULL) {
			FREE(pIfTable);
			pIfTable = NULL;
		}
		return 1;
		// Here you can use FormatMessage to find out why 
		// it failed.
	}
	if (pIfTable != NULL) {
		FREE(pIfTable);
		pIfTable = NULL;
	}
}

int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	FILETIME ftime, fexit, fsys, fuser, fstart;
	SYSTEMTIME stime;
	ULARGE_INTEGER now, sys, user;
	double percent;
	unsigned int i;

	printf("\n\"Process ID: %u\":[\t", processID);

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess) {
		return 1;
	}
	init();
	WCHAR procWChar[MAX_PATH];
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}
	DWORD namelen = GetProcessImageFileName(hProcess, procWChar, sizeof(procWChar) / sizeof(*procWChar));
	if (0 == namelen)
	{
		printf("Name was empty, skipping....");
		return 1;
	}
    _tprintf(TEXT("Process Name: %s\n"), szProcessName);

	wstring procName = wstring(procWChar);
	size_t lastPath = procName.find_last_of(L"\\");
	procName = procName.substr(lastPath + 1, procName.length() - lastPath - 1);

	PROCESS_MEMORY_COUNTERS_EX pmc;
	GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
	SIZE_T virtualMemUsedByMe = pmc.PrivateUsage;
	SIZE_T physMemUsedUsedByMe = pmc.WorkingSetSize;
	_tprintf(TEXT("Virtual Mem Used: %u Bytes    "), virtualMemUsedByMe);
	_tprintf(TEXT("Physical Mem Used: %u Bytes    "), physMemUsedUsedByMe);

	GetCpuUsage(processID);
	
	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
	{
		wstringstream modsString;
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				wstring modName = wstring((WCHAR*)szModName);
				
				if (findStringIC(modName, L"d3d") || findStringIC(modName, L"opengl"))
				{
					if (0 != i)
						modsString << L" ,";
					modsString << modName;
				}
				if(0 != i) printf(",");
				_tprintf(TEXT("\"    %s (0x%08X)\"  -  "), szModName, hMods[i]);
				printFileDescriptions(szModName);
			}
		}
		if (modsString.rdbuf()->in_avail() != 0)
			wcout << L"Process: " << procName << L":  " << modsString.str() << endl;
	}

	CloseHandle(hProcess);

	return 0;
}


int main(void)
{

	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return 1;

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		PrintModules(aProcesses[i]);
	}
	PrintNetwork();
	PrintIfTable();
	return 0;
}