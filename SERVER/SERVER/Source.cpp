#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define BUF_SIZE 8192

#include <windows.h> 
#include <winsock2.h> 
#include <iostream>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <mswsock.h>
#include <conio.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <sddl.h> 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

#define MAX_CLIENTS 100

HCRYPTPROV hProv = 0;
HCRYPTKEY publicKey = 0;
HCRYPTKEY sessionKey = 0;
HCRYPTKEY Key = 0;
DWORD SessionKeyLength = 0;
DWORD publicKeyLength = 0;
struct sockaddr_in addr;
SOCKET s;
int g_accepted_socket;
HANDLE g_io_port;
bool ac = FALSE;
bool ow = FALSE;

enum nextOperation
{
	HANDSHAKE0,
	HANDSHAKE1,
	ACTGET,
	CLOSECONN
};

struct client_ctx
{
	int socket;
	CHAR buf_recv[4096]; // ����� ������
	CHAR buf_send[4096]; // ����� ��������
	unsigned int sz_recv; // ������� ������
	unsigned int sz_send_total; // ������ � ������ ��������
	unsigned int sz_send; // ������ ����������
	 // ��������� OVERLAPPED ��� ����������� � ����������
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // ����� ��� WSARecv

	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTKEY hPubKey;
	HCRYPTKEY hPrivKey;
	HCRYPTKEY hSessionKey;

	char sessdata[1024];
	char buf[1024];
	BYTE dataPubKey[1024];
	DWORD pubKeyLen;
	nextOperation nextOperation;
};
struct client_ctx g_ctxs[1 + MAX_CLIENTS];

//����� ��������� �� ������
void PrintErrorAndExit(const char* error)
{
	printf("[server]: %s error!", error);
	exit(-1);
}

//���������� ��������� � ��������
void send_crypt_sched(char* buf, int idx)
{
	//�������� �����
	memset(g_ctxs[idx].buf_send, 0, 1024);
	//��������� �����
	memcpy(g_ctxs[idx].buf_send, buf, strlen(buf));
	//������������� �����
	DWORD dwDataLen = strlen(buf);
	CryptEncrypt(g_ctxs[idx].hSessionKey, NULL, TRUE, 0, (BYTE*)g_ctxs[idx].buf_send, &dwDataLen, 1024);
	g_ctxs[idx].buf_send[dwDataLen] = '\0';
	g_ctxs[idx].sz_send_total = dwDataLen + 3;
	g_ctxs[idx].sz_send = 0;
	strncpy((char*)g_ctxs[idx].buf_send + (int)dwDataLen, "CMD", 3);
}

//��������� ���������� �� ��
void get_os_version(DWORD idx)
{
	char buf[4096] = "";
	HKEY hKey;
	DWORD bufsize = 64;
	WCHAR buf_os[64];
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, "ProductName", NULL, NULL, (LPBYTE)buf_os, &bufsize);
		sprintf(buf, "%s", "Windows version: ");
		sprintf(buf + strlen(buf), "%s\n", buf_os);
	}
	send_crypt_sched(buf, idx);
}

//��������� �������� �������
void get_current_time(DWORD idx)
{
	char buf[4096] = "";
	//�������� ������� ��������� ���� � �����. ��������� ����� ���������� � ��������� ���������������� �������
	SYSTEMTIME sm;
	GetSystemTime(&sm);
	//
	sprintf(buf, "%s", "Time now: ");
	(sm.wDay > 9) ? sprintf(buf + strlen(buf), "%d.", sm.wDay) : sprintf(buf + strlen(buf), "0%lu.", sm.wDay);
	(sm.wMonth > 9) ? sprintf(buf + strlen(buf), "%lu.", sm.wMonth) : sprintf(buf + strlen(buf), "0%lu.", sm.wMonth);
	sprintf(buf + strlen(buf), "%lu ", sm.wYear);
	//
	(sm.wHour + 3 > 9) ? sprintf(buf + strlen(buf), "%d:", sm.wHour + 3) : sprintf(buf + strlen(buf), "0%d:", sm.wHour + 3);
	(sm.wMinute > 9) ? sprintf(buf + strlen(buf), "%d:", sm.wMinute) : sprintf(buf + strlen(buf), "0%d:", sm.wMinute);
	(sm.wSecond > 9) ? sprintf(buf + strlen(buf), "%d\n", sm.wSecond) : sprintf(buf + strlen(buf), "0%d\n", sm.wSecond);
	send_crypt_sched(buf, idx);
}

//��������� ������� � ������� ��������
void get_boot_time(DWORD idx)
{
	char buf[4096] = "";
	//�������� ���������� �����������, ��������� � ������� ������� �������
	int day, hour, min, sec, msec = GetTickCount64();
	hour = msec / (1000 * 60 * 60);
	min = msec / (1000 * 60) - hour * 60;
	sec = (msec / 1000) - (hour * 60 * 60) - min * 60;
	day = hour / 24;
	hour %= 24;
	//���������� � ������
	sprintf(buf, "%s", "Boot time: ");
	sprintf(buf + strlen(buf), " %d days ", day);
	(hour > 9) ? sprintf(buf + strlen(buf), "%d:", hour) : sprintf(buf + strlen(buf), "0%d:", hour);
	(min > 9) ? sprintf(buf + strlen(buf), "%d:", min) : sprintf(buf + strlen(buf), "0%d:", min);
	(sec > 9) ? sprintf(buf + strlen(buf), "%d\n", sec) : sprintf(buf + strlen(buf), "0%d\n", sec);
	send_crypt_sched(buf, idx);
}

//��������� ���������� �� ����������� ������
void get_memory_info(DWORD idx)
{
	char buf[4096] = "";
	MEMORYSTATUSEX state;
	state.dwLength = sizeof(state);
	//�������� ���������� � ������� ������������� �������� ���������� � ����������� ������
	GlobalMemoryStatusEx(&state);
	//���������� �������������� ������ � ���������
	sprintf(buf, "%d percent of memory in use.\n", state.dwMemoryLoad);
	//����� ���� ������������� �� ���������� ���
	sprintf(buf + strlen(buf), "%f total MB of physical memory.\n", (double)state.ullTotalPhys / 1024.0 / 1024.0);
	//��������� ���������� ������ � ������
	sprintf(buf + strlen(buf), "%f free MB of physical memory.\n", (double)state.ullAvailPhys / 1024.0 / 1024.0);
	//������ ����� �������� � ������
	sprintf(buf + strlen(buf), "%f total MB of paging file.\n", (double)state.ullTotalPageFile / 1024.0 / 1024.0);
	//��������� ����� ������ � ����� ��������
	sprintf(buf + strlen(buf), "%f free MB of paging file.\n", (double)state.ullAvailPageFile / 1024.0 / 1024.0);
	//����� ����� ����������� ������ � ������
	sprintf(buf + strlen(buf), "%f total MB of virtual memory.\n", (double)state.ullTotalVirtual / 1024.0 / 1024.0);
	//����� ��������� ����������� ������
	sprintf(buf + strlen(buf), "%f free MB of virtual memory.\n", (double)state.ullAvailVirtual / 1024.0 / 1024.0);
	//����� ��������� ����������� ����������� ������
	sprintf(buf + strlen(buf), "%f free MB of extended memory.\n", (double)state.ullAvailExtendedVirtual / 1024.0 / 1024.0);
	send_crypt_sched(buf, idx);
}

//��������� ���������� � ������ � �������
void get_drive_info(DWORD idx)
{
	char buf[4096] = "";
	//�����-������� �����, � ������� �������� ��� ��������� �����
	DWORD drives = GetLogicalDrives();
	WCHAR driveName[26][4] = { 0 };
	WCHAR FileSystemName[100];
	DWORD SectorsPerCluster, BytesPerSector, NumberOfFreeClusters, TotalNumberOfClusters;
	unsigned count = 0;
	//������������� �����-������� �����, ���� � ��� ���� �����, ����������
	for (unsigned i = 0; i < 26; i++)
	{
		if ((drives & (1 << i)))
		{
			driveName[count][0] = WCHAR(65 + i);
			driveName[count][1] = ':';
			driveName[count][2] = '\\';
			count++;
		}
	}
	//������������� ��� ��������� �����
	for (unsigned i = 0; i < count; i++)
	{
		for (int j = 0; j < 3; j++)
			sprintf(buf + strlen(buf), "%lc", driveName[i][j]);
		switch (GetDriveTypeW((LPWSTR)driveName[i]))
		{
		case DRIVE_UNKNOWN:
			sprintf(buf + strlen(buf), "Type: unknown type; ");
			break;
		case DRIVE_FIXED:
			sprintf(buf + strlen(buf), "Type: hard disk; ");
			break;
		case DRIVE_REMOTE:
			sprintf(buf + strlen(buf), "Type: remote (network) disk; ");
			break;
		case DRIVE_REMOVABLE:
			sprintf(buf + strlen(buf), "Type: flash card; ");
			break;
		case DRIVE_CDROM:
			sprintf(buf + strlen(buf), "Type: CD-ROM disk; ");
			break;
		case DRIVE_RAMDISK:
			sprintf(buf + strlen(buf), "Type: RAM disk; ");
			break;
		}
		GetDiskFreeSpaceW((LPWSTR)driveName[i], &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters, &TotalNumberOfClusters);
		sprintf(buf + strlen(buf), "Free space: %f GB\n", (double)NumberOfFreeClusters * (double)SectorsPerCluster * (double)BytesPerSector / 1024.0 / 1024.0 / 1024.0);
	}
	send_crypt_sched(buf, idx);
}

//��������� ���������� � ������ ������������� �� ����/�����/���� �������
void get_access_rights(char* path, DWORD idx)
{
	char buf[4096] = "";
	//����� ������� � ���������� �����/�����
	PACL pDACL = NULL;
	char pathCopy[200] = { 0 };
	strcpy(pathCopy, path);
	printf("[server]: %s\n", path);
	bool key = false;
	char* part1 = strtok(pathCopy, "\\");
	//���������, �� ���� �� ������� ���� ���������
	if (!strcmp(part1, "HKEY_CLASSES_ROOT") || (!strcmp(part1, "HKEY_CURRENT_USER"))
		|| (!strcmp(part1, "HKEY_LOCAL_MACHINE")) || (!strcmp(part1, "HKEY_USERS"))
		|| (!strcmp(part1, "HKEY_CURRENT_CONFIG")))
		key = TRUE;
	else
		key = FALSE;

	PSECURITY_DESCRIPTOR pSD = NULL;
	ACL_SIZE_INFORMATION aclInfo;
	SID_NAME_USE sid_nu;
	char* subkey = NULL;
	//��������� �����/�����
	if (!key)
	{
		if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
		{
			PrintErrorAndExit("GetNamedSecurityInfo()");
			return;
		}
	}
	//��������� ����� �������
	else
	{
		HKEY res = 0;
		part1 = strtok(path, "\\");
		subkey = strtok(NULL, "\0");
		if (!strcmp(part1, "HKEY_CLASSES_ROOT"))
			RegOpenKey(HKEY_CLASSES_ROOT, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_CURRENT_USER"))
			RegOpenKey(HKEY_CURRENT_USER, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_LOCAL_MACHINE"))
			RegOpenKey(HKEY_LOCAL_MACHINE, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_USERS"))
			RegOpenKey(HKEY_USERS, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_CURRENT_CONFIG"))
			RegOpenKey(HKEY_CURRENT_CONFIG, (LPCSTR)subkey, &res);
		else
			PrintErrorAndExit("RegOpenKey()");
		if (GetSecurityInfo(res, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
			PrintErrorAndExit("GetSecurityInfo()");
	}
	//��������� �� DACL, ����, �������, ��� ������
	if (!GetAclInformation(pDACL, &aclInfo, sizeof(aclInfo), AclSizeInformation))
	{
		PrintErrorAndExit("GetAclInformation()");
		return;
	}
	//������������� ������
	DWORD ac_count = aclInfo.AceCount;
	for (DWORD i = 0; i < ac_count; i++)
	{
		DWORD dwSize = 256;
		LPTSTR user = new TCHAR[dwSize];
		LPTSTR domain = new TCHAR[dwSize];

		void* ace;
		// �������� ������� ������
		if (GetAce(pDACL, i, &ace))//���������� ACE �� ��������� �������
		{
			PSID* pSID = (PSID*) & ((ACCESS_ALLOWED_ACE*)ace)->SidStart;//����� SID
			//��������� �������// SID//��� �� �������////��� ������//������ ������
			if (LookupAccountSid(NULL, pSID, user, &dwSize, domain, &dwSize, &sid_nu))
			{
				char* StringSid = NULL;
				ConvertSidToStringSid(pSID, &StringSid);
				sprintf(buf + strlen(buf), "SID: %s; ", StringSid);
				sprintf(buf + strlen(buf), "Account: %s; ", user);

				//��� ACE
				//ACE � ����������� �� ������
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
					sprintf(buf + strlen(buf), "Type: Allowed; ");
				//ACE � ������� � �������
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
					sprintf(buf + strlen(buf), "Type: Denied; ");
				//ACE ��������������� ��� �������� �������������
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
					sprintf(buf + strlen(buf), "Type: System; ");
				//ACE ���������� ������
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
					sprintf(buf + strlen(buf), "Type: System Audit; ");
				//
				//����� � ACE
				sprintf(buf + strlen(buf), "Rights: ");
				//����� �� ��������� ���������
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & WRITE_OWNER) == WRITE_OWNER)
					sprintf(buf + strlen(buf), "Change Owner, ");
				//����� �� ��������� DACL
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & WRITE_DAC) == WRITE_DAC)
					sprintf(buf + strlen(buf), "Write DAC, ");
				//����� ��������
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & DELETE) == DELETE)
					sprintf(buf + strlen(buf), "Delete, ");
				//����� �� ������ (����������)
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
					sprintf(buf + strlen(buf), "Read, ");
				//����� �� ������ (����������)
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
					sprintf(buf + strlen(buf), "Write, ");
				//����� �� ���������� (����������)
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
					sprintf(buf + strlen(buf), "Execute, ");
				//����� �� �������������
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & SYNCHRONIZE) == SYNCHRONIZE)
					sprintf(buf + strlen(buf), "Synchronize, ");
				//����� �� ������ ACL
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & READ_CONTROL) == READ_CONTROL)
					sprintf(buf + strlen(buf), "Read control, ");
				sprintf(buf + strlen(buf) - 2, ".");
				sprintf(buf + strlen(buf), "\n");
			}
		}
		delete[] user;
		delete[] domain;
	}
	send_crypt_sched(buf, idx);
}

//��������� ��������� �����/�����/����� �������
void get_object_owner(char* path, DWORD idx)
{
	PACL pDACL = NULL;
	char pathCopy[200] = { 0 };
	strcpy(pathCopy, path);
	printf("[server]: %s\n", path);
	bool key = false;
	char* part1 = strtok(pathCopy, "\\");
	//���������, �� ���� �� ������� ���� ���������
	if (!strcmp(part1, "HKEY_CLASSES_ROOT") || (!strcmp(part1, "HKEY_CURRENT_USER")) || (!strcmp(part1, "HKEY_LOCAL_MACHINE")) || (!strcmp(part1, "HKEY_USERS")) || (!strcmp(part1, "HKEY_CURRENT_CONFIG")))
		key = TRUE;
	else
		key = FALSE;

	PSID pOwnerSid = NULL; // SID of file/folder/key
	PSECURITY_DESCRIPTOR pSD = NULL; // security descriptor (ptr)
	SID_NAME_USE sid_nu; // struct that determine type of write
	char* subkey = NULL;
	DWORD dwSize = 256;
	LPTSTR user = new TCHAR[dwSize];
	LPTSTR domain = new TCHAR[dwSize];
	ACL_SIZE_INFORMATION aclInfo;

	char buf[BUF_SIZE] = { 0 };
	//��������� ����� ��� �����
	if (!key)
	{
		//�������� ���������� � �����
		if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			PrintErrorAndExit("GetNamedSecurityInfo()");
			return;
		}
	}
	//��������� ����� �������
	else
	{
		HKEY res;
		part1 = strtok(path, "\\");
		subkey = strtok(NULL, "\0");
		//�������� ���������� � �����
		if (!strcmp(part1, "HKEY_CLASSES_ROOT"))
			RegOpenKey(HKEY_CLASSES_ROOT, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_CURRENT_USER"))
			RegOpenKey(HKEY_CURRENT_USER, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_LOCAL_MACHINE"))
			RegOpenKey(HKEY_LOCAL_MACHINE, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_USERS"))
			RegOpenKey(HKEY_USERS, (LPCSTR)subkey, &res);
		else if (!strcmp(part1, "HKEY_CURRENT_CONFIG"))
			RegOpenKey(HKEY_CURRENT_CONFIG, (LPCSTR)subkey, &res);
		else
		{
			PrintErrorAndExit("RegOpenKey()");
			return;
		}
		if (GetSecurityInfo(res, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			PrintErrorAndExit("GetSecurityInfo()");
			return;
		}
	}
	//���� 
	if (pSD == NULL)
	{
		sprintf(buf + strlen(buf), "Security descriptor is empty\n");
		return;
	}

	LookupAccountSid(NULL, pOwnerSid, user, &dwSize, domain, &dwSize, &sid_nu);
	LPSTR StringSid = NULL;
	ConvertSidToStringSid(pOwnerSid, &StringSid);
	sprintf(buf + strlen(buf), " SID: %s  ", StringSid);
	sprintf(buf + strlen(buf), "Account: %s\n", user);
	delete[] user;
	delete[] domain;
	send_crypt_sched(buf, idx);
}

//������� �������� �������� ������ �� ������
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = (char*)g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

//������ ���������������� �� �������
void crypt_init_server(DWORD idx, int part)
{
	if (part == 1)
	{
		//
		//������ ���������� ��������� � ��������� �����,
		//����� ���� ��������� ���������� �������
		//

		//
		//������ ���������� ��������� ����, ������� ���
		//��������� ������ � ���������� ������� �������
		//
		if(CryptAcquireContext(&g_ctxs[idx].hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
			printf("[server]: cryptographic provider initialized\n");
		if(!CryptGenKey(g_ctxs[idx].hProv, AT_KEYEXCHANGE, 1024 << 16, &g_ctxs[idx].hKey))
			PrintErrorAndExit("CryptGenKey()");
		if(!CryptGetUserKey(g_ctxs[idx].hProv, AT_KEYEXCHANGE, &g_ctxs[idx].hPubKey))
			PrintErrorAndExit("CryptGetUserKey()");
		if (!CryptExportKey(g_ctxs[idx].hPubKey, 0, PUBLICKEYBLOB, 0, g_ctxs[idx].dataPubKey, &g_ctxs[idx].pubKeyLen))
			PrintErrorAndExit("CryptExportKey()");
		g_ctxs[idx].sz_send_total = g_ctxs[idx].pubKeyLen + 3;
		g_ctxs[idx].sz_send = 0;
		memset(g_ctxs[idx].buf_send, 0, 1024);
		memcpy(g_ctxs[idx].buf_send, g_ctxs[idx].dataPubKey, g_ctxs[idx].pubKeyLen);
		strncpy((char*)g_ctxs[idx].buf_send + g_ctxs[idx].pubKeyLen, "END", 3);
	}
	else if (part == 2)
	{
		//
		//������ �������������� ��������� ������ ���������,
		//����� ���� ��������� ���� ���������
		//
		memcpy(g_ctxs[idx].sessdata, (char*)g_ctxs[idx].buf_recv, g_ctxs[idx].sz_recv - 3);
		if (!CryptGetUserKey(g_ctxs[idx].hProv, AT_KEYEXCHANGE, &g_ctxs[idx].hPrivKey))
			PrintErrorAndExit("CryptGetUserKey()");
		if (!CryptImportKey(g_ctxs[idx].hProv, (BYTE*)g_ctxs[idx].sessdata, g_ctxs[idx].sz_recv - 3, 0, 0, &g_ctxs[idx].hSessionKey))
			PrintErrorAndExit("CryptImportKey()");
		CryptDestroyKey(g_ctxs[idx].hKey);
	}
}

//������� �������� �������� �������� �������������� ������ � ����� 
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = (char*)g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

//������� ��������� ����� �������� ����������� �������
void add_accepted_connection()
{
	DWORD i;
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, * remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv,
				sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
				(struct sockaddr**) & local_addr, &local_addr_sz, (struct sockaddr**)
				& remote_addr, &remote_addr_sz);

			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);
			printf("Connection %u created, remote IP: %u.%u.%u.%u\n", i,
				(ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);

			g_ctxs[i].socket = g_accepted_socket;
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}

			g_ctxs[i].nextOperation = HANDSHAKE0;
			g_ctxs[i].pubKeyLen = 1024;
			schedule_read(i);
			return;
		}
	}

	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

//������� �������� �������� ������ ����������  
void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

//������� ���������, ������ �� ��������� ���������
int is_recieved(DWORD idx, int* len)
{
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	for (int i = 0; i < 4094; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == 'E' && g_ctxs[idx].buf_recv[i + 1] == 'N' && g_ctxs[idx].buf_recv[i + 2] == 'D')
		{
			g_ctxs[idx].buf_recv[i] = '\0';
			g_ctxs[idx].buf_recv[i + 1] = '\0';
			g_ctxs[idx].buf_recv[i + 2] = '\0';
			*len = i;
			return 1;
		}
	}
	return 0;
}

//������� ������������ ������� ������
int handler(DWORD idx)
{
	if (!strncmp((char*)g_ctxs[idx].buf_recv, "HANDSHAKE", 9))
	{
		//������ �������� HS � ����, ���� ������ ������, ����� ���� ���������� ����, HS �����������
		g_ctxs[idx].nextOperation = HANDSHAKE1;
		crypt_init_server(idx, 1);
		return 1;
	}
	if (g_ctxs[idx].nextOperation == HANDSHAKE1)
	{
		g_ctxs[idx].nextOperation = ACTGET;
		crypt_init_server(idx, 2);
		return 1;
	}
	if (g_ctxs[idx].nextOperation == ACTGET)
	{
		DWORD len = g_ctxs[idx].sz_recv - 3;
		CryptDecrypt(g_ctxs[idx].hSessionKey, NULL, TRUE, 0, (BYTE*)g_ctxs[idx].buf_recv, &len);
		if (ac == TRUE) {
			ac = FALSE;
			get_access_rights((char*)g_ctxs[idx].buf_recv, idx);
		}
		else if (ow == TRUE)
		{
			ow = FALSE;
			get_object_owner((char*)g_ctxs[idx].buf_recv, idx);

		}
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "1", 12) == 0)
			get_os_version(idx);
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "2", 2) == 0)
			get_current_time(idx);
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "3", 2) == 0)
			get_boot_time(idx);
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "4", 2) == 0)
			get_memory_info(idx);
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "5", 2) == 0)
			get_drive_info(idx);
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "6", 2) == 0)
		{
			ac = TRUE;
			return 1;
		}
		else if (strncmp((char*)g_ctxs[idx].buf_recv, "7", 2) == 0)
		{
			ow = TRUE;
			return 1;
		}
		return 1;
	}
}

//�������� ������� ��������� ������ �����/������ 
void io_serv()
{
	//������������� WSA
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
	//�������� ������ ������������� 
	struct sockaddr_in addr;
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	//�������� ����� ���������� 
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
		PrintErrorAndExit("CreateIoCompletionPort");
	//��������� ��������� ������ ��� �������� �������� ���������� 
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	printf("ENTER PORT: ");
	int PORT;
	scanf("%d", &PORT);
	addr.sin_port = htons(PORT);
	//�������� ������������� �����
	if (bind(s, (struct sockaddr*) & addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
		printf("Error bind() or listen()\n");
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	//������������� ������������� ������ s � ����� io_port.   
	//� �������� ����� ��� ��������������� ������ ������������ 0   
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	//����� �������� �������� �����������. 
	schedule_accept();
	//����������� ���� �������� ������� � ����������� ��������� 
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		//�������� ������� � ������� 1 �������
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			//��������� ����������� � ���������� ��������
			if (key == 0)
			{
				g_ctxs[0].sz_recv += transferred;
				//�������� ����������� � ������ �������� ���������� 
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				//����� ��������� ������� �� ���������� �������� �� �������. 
				//���� key - ������ �
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					//������ �������: 
					int len; 
					if (transferred == 0)
					{
						//���������� ���������
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					//���� ������ ��������� ������, �� ������������ ����� � ������ ��� ����������
					if (is_recieved(key, &len))
					{
						if (handler(key))
							schedule_write(key);
						else
						{
							//��������
							g_ctxs[key].sz_recv = 0;
							g_ctxs[key].sz_send = 0;
							g_ctxs[key].sz_send_total = 0;
							schedule_read(key);
						}
					}
					else
						schedule_read(key);
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					//������ ���������� 
					g_ctxs[key].sz_send += transferred;
					//���� ������ ���������� �� ��������� - ���������� ���������� 
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
						schedule_write(key);
					else
					{
						if (g_ctxs[key].nextOperation == CLOSECONN)
						{
							CancelIo((HANDLE)g_ctxs[key].socket);
							PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						}
						else
						{
							//
							//������ ���������� ���������, �������� ��� ������������,
							//�������� � ���� ������� �� ���������� ������
							//
							g_ctxs[key].sz_recv = 0;
							g_ctxs[key].sz_send = 0;
							g_ctxs[key].sz_send_total = 0;
							schedule_read(key);
						}
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					//��� ������������ ���������, ����� ����� ���� ������ 
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf("[server]: connection %u closed\n", key);
				}
			}
		}
	}
}

void main(int argc, char const* argv[])
{
	io_serv();
	return;
}