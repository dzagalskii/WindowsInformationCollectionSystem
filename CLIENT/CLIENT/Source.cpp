#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN  
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h> 
#include <iostream>
#include <windows.h>  
#include <winsock2.h>  
#include <ws2tcpip.h>    
#include <string.h> 
#include <stdlib.h>
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")  

HCRYPTPROV hProv;
HCRYPTKEY Key;
HCRYPTKEY publicKey;
HCRYPTKEY privateKey;
BYTE* pbKeyBlob;
DWORD size_of_public = 0;
SOCKET s;
struct sockaddr_in addr;
struct sockaddr_in TCP_addr;
SOCKET TCP_socket;
HCRYPTKEY hSessionKey;

//Функция получения сообщения
int WSARecieve(char* retData, int* len)
{
	char incData[4096] = "\0";
	int rcvCount; int curlen = 0; int retcode = 0;
	do
	{
		int i;
		rcvCount = recv(TCP_socket, incData, sizeof(incData), 0);
		for (i = curlen; i <= curlen + rcvCount; i++)
		{
			if (incData[i] == 'E' && incData[i + 1] == 'N' && incData[i + 2] == 'D')
			{
				incData[i] = '\0'; incData[i + 1] = '\0'; incData[i + 2] = '\0';
				*len = i; goto stop;
			}
			if (incData[i] == 'C' && incData[i + 1] == 'M' && incData[i + 2] == 'D')
			{
				incData[i] = '\0'; incData[i + 1] = '\0'; incData[i + 2] = '\0';
				*len = i; retcode = 1; goto stop;
			}
			if (i > 4095)
			{
				*len = 4096;
				goto stop;
			}
		}
	stop:
		break;
	} while (rcvCount > 0);
	if (*len != 0)
		memcpy(retData, incData, *len);
	return retcode;
}

//Функция отправки сообщения
void WSASend(char* msg, int len)
{
	char toSend[4096] = "\0";
	memcpy(toSend, msg, len);
	strncpy(toSend + len, "END", 3);
	len += 3;
	int sent = 0;
	int flags = 0;
	while (sent < len)
	{
		int res = send(TCP_socket, toSend + sent, len - sent, flags);
		if (res < 0)
			return;
		sent += res;
	}
	return;
}

//Функция выводит сообщения об ошибках
void PrintErrorAndExit(const char* error)
{
	printf("[client]: %s error!", error);
	exit(-1);
}

//Функция выводит все команды пользователя
void PrintAllCommands()
{
	printf("[client]: ### ### ###\n");
	printf("[client]: 1 - OS information\n");
	printf("[client]: 2 - current time\n");
	printf("[client]: 3 - OS time\n");
	printf("[client]: 4 - memory information\n");
	printf("[client]: 5 - drive information\n");
	printf("[client]: 6 - file access right\n");
	printf("[client]: 7 - file owner\n");
	printf("[client]: 8 - exit\n");
	printf("[client]: ");
}

//Функция обеспечивает работу криптопровайдера
void crypt_init_client()
{
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTKEY hOpenKey;
	
	int  serverKeyLen = 0;
	char serverKey[1024] = "\0";
	BYTE data[1024] = "\0";
	DWORD dataSize = 1024;

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL)) {// Получение дескриптора криптопровайдера
		printf("[client]: Cryptographic provider initialized\n");
	}
	else {
		if (GetLastError() == NTE_BAD_KEYSET) {//контейнера нет
			if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				printf("[client]: New Cryptographic container created\n");

		}
	}
	CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey); //генерируем сессионный ключ RC4

	WSARecieve(serverKey, &serverKeyLen);

	CryptImportKey(hProv, (BYTE*)serverKey, serverKeyLen, 0, 0, &hOpenKey); //добавляем открытый ключ сервера в хранилище

	CryptExportKey(hSessionKey, hOpenKey, SIMPLEBLOB, 0, data, &dataSize); //получем сеансовый ключ


	WSASend((char*)data, dataSize);
	CryptDestroyKey(hOpenKey);
}

//Функция зашифровывает сообщение
void Encrypt(char* buf, int* len)
{
	DWORD dwDataLen = strlen(buf);
	CryptEncrypt(hSessionKey, NULL, TRUE, 0, (BYTE*)buf, &dwDataLen, 1024);
	buf[dwDataLen] = '\0';
	*len = dwDataLen;
}

//Функция инициализирует соединение
int WSAInit(unsigned int addr_in, unsigned short port_in)
{
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);

	// Заполнение структуры с адресом удаленного узла 
	memset(&TCP_addr, 0, sizeof(TCP_addr));
	TCP_addr.sin_family = AF_INET;
	TCP_addr.sin_port = htons(port_in);
	TCP_addr.sin_addr.s_addr = addr_in;

	// Создание TCP-сокета 
	TCP_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (TCP_socket < 0)
		return 0;

	if (connect(TCP_socket, (struct sockaddr*) & TCP_addr, sizeof(TCP_addr)) != 0)
	{
		closesocket(TCP_socket);
		return 0;
	}
	char p[10] = "HANDSHAKE";
	WSASend(p, 9);
	return 1;
}

//Функция отправки зашифрованного сообщения
void WSASendEncrypted(char* msg)
{
	char enc[4096] = "\0";
	strncpy(enc, msg, strlen(msg));
	int len;
	Encrypt(enc, &len);
	WSASend(enc, len);
}

//Функция деинициализирует соединение
void WSADeinit()
{
	closesocket(TCP_socket);
	WSACleanup();
}

//Главная функция = ввод запрос пользователя + вывод ответа сервера пользователю
void client_main()
{
	while (1)
	{
		PrintAllCommands();
		char cmd[256] = "\0";
		scanf("%s", &cmd);
		int cmd2 = atoi(cmd);
		WSASendEncrypted(cmd);
		if (cmd2 == 6 || cmd2 == 7)
		{
			printf("[server]: enter path: ");
			char for_path[100] = { 0 };
			gets_s(for_path);
			gets_s(for_path);
			WSASendEncrypted(for_path);
		}
		char data[1024] = "\0"; 
		int len;
		if (WSARecieve(data, &len))
		{
			DWORD size = len;
			CryptDecrypt(hSessionKey, NULL, TRUE, 0, (BYTE*)data, &size);
			printf("[client][server]:\n%s\n", data);
		}
		else
			printf("[client]: Error!\n");
	}
}

int main()
{
	setlocale(LC_ALL, "Russian");
	//char IP[20] = "127.0.0.1";
	//int PORT = 5555;
	char IP[20];
	int PORT;
	printf("ENTER IP-ADDRESS: ");
	scanf("%s", &IP);
	printf("ENTER PORT: ");
	scanf("%d", &PORT);
	printf("\nInitialization...\n\n");

	if (WSAInit(inet_addr(IP), PORT))
	{
		printf("Connected to %s:%d\n", IP, PORT);
		crypt_init_client();
		client_main();
		WSADeinit();
	}
	else
	{
		printf("Connection error\n");
	}
	return 0;
}
