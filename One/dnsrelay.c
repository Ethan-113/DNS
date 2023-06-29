#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <windows.h>
#include <time.h>
#include "difinition.h"
#include "trie.c"
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib") //加载 ws2_32.dll

Translate DNS_table[AMOUNT];
Translate newDNS_table[300];
IDTransform IDTransTable[AMOUNT];
int IDcount = 0;
char url[LENGTH];
char nIP[16];
char recvbuf_temp[BUF_SIZE];
char send_addr[LENGTH], rcv_addr[LENGTH];
unsigned short send_port, rcv_port;
SYSTEMTIME sys;
int Day, Hour, Min, Sec, Msec;
int Day1, Hour1, Min1, Sec1;
int Day2, Hour2, Min2, Sec2;
char sendbuf[BUF_SIZE];
char recvbuf[BUF_SIZE];
char idbuf[2];
int number_level=-1;
char outerDns[16];
int len;



int GetTable(char* path, pNode root);
void GetUrl(char* recvbuf, int recvnum);
unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone);
void DisplayInfo(unsigned short newID, int result, int level);
int printBinary(unsigned char byte,int place);
void GetIP(char* recvbuf, int Recv);



//函数1:获取域名解析表
int GetTable(char* path, pNode root) {
    int i = 0, j = 0;
    int num = 0;
    char* Temp[AMOUNT];
    FILE* fp = fopen(path, "ab+");
    if (!fp)
    {
        printf("打开文件失败\n");
        exit(-1);
    }
    char* reac;
    while (i < AMOUNT - 1)
    {
        Temp[i] = (char*)malloc(sizeof(char) * 200);
        if (fgets(Temp[i], 200, fp) == NULL)
            break;
        i++;
    }
    if (i == AMOUNT - 1)
        printf("DNS记录存储内存已满\n");

    for (j; j < i; j++)
    {
        char* ex1 = strtok(Temp[j], " ");
        char* ex2 = strtok(NULL, " ");
        if (ex2 == NULL)
        {
            printf("记录格式不正确\n");
        }
        else
        {
            Translate t1 = { ex1, ex2 };
            printf("%s     ",ex1);
            printf("%s", ex2);
            DNS_table[num].domain = ex2;
            DNS_table[num].IP = ex1;
            insert(root, t1.domain, num);
            num++;
        }
    }
    fclose(fp);
    printf("本地DNS记录加载成功\n");

    return num;
}


void GetUrl(char* recvbuf, int recvnum)
{
    char urlname[LENGTH];
    int i = 0, j, k = 0;

    memset(url, 0, LENGTH);
    memcpy(urlname, &(recvbuf[sizeof(DNSHDR)]), recvnum - 12);

    int len = strlen(urlname);


    while (i < len)
    {
        if (urlname[i] > 0 && urlname[i] <= 63)
            for (j = urlname[i], i++; j > 0; j--, i++, k++)
                url[k] = urlname[i];

        if (urlname[i] != 0) {
            url[k] = '.';
            k++;
        }
    }

    url[k] = '\0';
}


unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone)
{
    srand(time(NULL));
    IDTransTable[IDcount].oldID = OldID;
    IDTransTable[IDcount].client = temp;
    IDTransTable[IDcount].done = ifdone;
    IDcount++;

    return (unsigned short)(IDcount - 1);
}


void DisplayInfo(unsigned short newID, int find, int level) {
    //获取当前时间
    time_t t = time(NULL);
    struct tm* t_info = localtime(&t);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t_info);

    clock_t start, stop;
    double duration;
    unsigned short Milliseconds;
    char recvbuf_temp[BUF_SIZE];

    if (level == 1) {

    }
    else if (level == 2) {
        struct sockaddr_in client = IDTransTable[newID].client;
        char ipTemp[40];
        strcpy(ipTemp, inet_ntoa(client.sin_addr));
        printf("\n%d:  %s  Client  %s     ", number_level, time_str, ipTemp);
        if (find == NOTFOUND) {
            printf("中继 域名: %s\n", url);
            //printf("中继 域名: %s IP: %s\n", url, nIP);
        }
        else {
            if (strcmp(DNS_table[find].IP, "0.0.0.0") == 0) {
                printf("域名不存在\n");
            }
            else if (find==-2) {
                printf("收到回复数据报 中继 域名: %s  IP: %s\n", url, nIP);
            }
            else
            {
                printf("本地 域名: %s  IP: %s\n", url, DNS_table[find].IP);
            }
        }
    }
    else if (level == 3) {
        struct sockaddr_in client = IDTransTable[newID].client;
        char ipTemp[40];
        strcpy(ipTemp, inet_ntoa(client.sin_addr));
        char server_recvbuf[2];
        if (find == NOTFOUND) {//本地文件没找到该域名
                struct sockaddr_in client = IDTransTable[newID].client;
                char ipTemp[40];
                strcpy(ipTemp, inet_ntoa(client.sin_addr));
                printf("%d :没有在本地内存找到\n   ID:%02x%02x -> %02x%02x\n   请求报文:\n   SERVER: %s (%d bytes)  ", number_level, idbuf[0], idbuf[1], recvbuf[0], recvbuf[1], ipTemp, len);
                for (int i = 0; i < len; i++)
                    printf("%02X ", recvbuf[i]);
                printf("\n   ID %02x%02x,  QR %d, Opcode %d%d%d%d, AA %d,TC %d,RD %d,RA %d,Z %d%d%d,RCODE %d%d%d%d\n", recvbuf[0], recvbuf[1],
                       printBinary(recvbuf[2], 0),
                       printBinary(recvbuf[2], 1), printBinary(recvbuf[2], 2), printBinary(recvbuf[2], 3), printBinary(recvbuf[3], 4),
                       printBinary(recvbuf[2], 5),
                       printBinary(recvbuf[2], 6),
                       printBinary(recvbuf[2], 7),
                       printBinary(recvbuf[3], 0),
                       printBinary(recvbuf[3], 1), printBinary(recvbuf[3], 2), printBinary(recvbuf[3], 3),
                       printBinary(recvbuf[3], 4), printBinary(recvbuf[3], 5), printBinary(recvbuf[3], 6), printBinary(recvbuf[3], 7)
                );
                printf("   QDCOUNT %02x%02x, ANCOUNT %02x%02x, NSCOUNT %02x%02x, ARCOUNT %02x%02x\n",
                       recvbuf[4], recvbuf[5],
                       recvbuf[6], recvbuf[7],
                       recvbuf[8], recvbuf[9],
                       recvbuf[10], recvbuf[11]);
                printf("域名：%s IP: %s\n", url,nIP);
                printf("   %s  \n", time_str);//时间
            }
            else if(find == -2)//客户端接收
        {
            struct sockaddr_in client = IDTransTable[newID].client;
            char ipTemp[40];
            strcpy(ipTemp, inet_ntoa(client.sin_addr));
            printf("   响应报文:\n   SERVER: %s (%d bytes)  ", outerDns, len);
            for (int i = 0; i < len; i++)
                if (i == 1) {
                    printf("%02X ", recvbuf[1]);
                } else
                    printf("%02X ", recvbuf[i]);
            printf("\n   ID %02x%02x,  QR %d, Opcode %d%d%d%d, AA %d,TC %d,RD %d,RA %d,Z %d%d%d,RCODE %d%d%d%d\n",
                   recvbuf[0], recvbuf[1],
                   printBinary(recvbuf[2], 0),
                   printBinary(recvbuf[2], 1), printBinary(recvbuf[2], 2), printBinary(recvbuf[2], 3),
                   printBinary(recvbuf[3], 4),
                   printBinary(recvbuf[2], 5),
                   printBinary(recvbuf[2], 6),
                   printBinary(recvbuf[2], 7),
                   printBinary(recvbuf[3], 0),
                   printBinary(recvbuf[3], 1), printBinary(recvbuf[3], 2), printBinary(recvbuf[3], 3),
                   printBinary(recvbuf[3], 4), printBinary(recvbuf[3], 5), printBinary(recvbuf[3], 6),
                   printBinary(recvbuf[3], 7)
            );
            printf("   QDCOUNT %02x%02x, ANCOUNT %02x%02x, NSCOUNT %02x%02x, ARCOUNT %02x%02x\n",
                   recvbuf[4], recvbuf[5],
                   recvbuf[6], recvbuf[7],
                   recvbuf[8], recvbuf[9],
                   recvbuf[10], recvbuf[11]);
            printf("\n");
        }
        else//本地文件找到该域名
        {
            struct sockaddr_in client = IDTransTable[newID].client;
            char ipTemp[40];
            strcpy(ipTemp, inet_ntoa(client.sin_addr));
            printf("%d :在本地内存找到\nSERVER: %s (%d bytes)  ", number_level, ipTemp, len);
            for (int i = 0; i < len; i++)
                printf("%02X ", recvbuf[i]);
            printf("\n      ID %02x%02x,  QR %d, Opcode %d%d%d%d, AA %d,TC %d,RD %d,RA %d,Z %d%d%d,RCODE %d%d%d%d\n", recvbuf[0], recvbuf[1],
                   printBinary(recvbuf[2], 0),
                   printBinary(recvbuf[2], 1), printBinary(recvbuf[2], 2), printBinary(recvbuf[2], 3), printBinary(recvbuf[3], 4),
                   printBinary(recvbuf[2], 5),
                   printBinary(recvbuf[2], 6),
                   printBinary(recvbuf[2], 7),
                   printBinary(recvbuf[3], 0),
                   printBinary(recvbuf[3], 1), printBinary(recvbuf[3], 2), printBinary(recvbuf[3], 3),
                   printBinary(recvbuf[3], 4), printBinary(recvbuf[3], 5), printBinary(recvbuf[3], 6), printBinary(recvbuf[3], 7)
            );
            printf("      QDCOUNT %02x%02x, ANCOUNT %02x%02x, NSCOUNT %02x%02x, ARCOUNT %02x%02x\n",
                   recvbuf[4], recvbuf[5],
                   recvbuf[6], recvbuf[7],
                   recvbuf[8], recvbuf[9],
                   recvbuf[10], recvbuf[11]);
            printf("    %s  \n", time_str);//时间
            printf("域名: %s\n", url);
            printf("\n");
        }
    }
}

//打印一个16进制数的2进制的某一位
int printBinary(unsigned char byte,int place) {
    int i;
    for (i = 7; i >= 0; i--) {
        if(i==7-place)
            return ((byte >> i) & 1);
    }
}

BOOL ISA (char* recvbuf){
    int num = 12;
    unsigned char ipVersion[1];
    memcpy(ipVersion, recvbuf+num, 1);
    while(ipVersion[0] != 0){
        num = num + ipVersion[0] + 1;
        memcpy(ipVersion, recvbuf+num, 1);
    }
    num = num +2;
    memcpy(ipVersion, recvbuf+num, 1);

    if(ipVersion[0] == 0x01)
        //A类型
        return TRUE;
    else
        return FALSE;
}

//只获得A类型的报文中包含的IP地址
void GetIP(char* recvbuf, int Recv) {
    if(ISA(recvbuf)) {
        unsigned char *lastResourceRecord = (unsigned char *) recvbuf + Recv - 4;

        unsigned char ipAddress[4];
        memcpy(ipAddress, lastResourceRecord, 4);

        snprintf(nIP, sizeof(nIP), "%d.%d.%d.%d", ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
    }
}


//主函数
int main(int argc, char** argv) {
    WSADATA wsaData;
    SOCKET socketServer, socketLocal;
    SOCKADDR_IN serverName, clientName, localName;
    char tablePath[50];
    int iLen_cli, iSend, iRecv;
    int num;
    int mod, count;
    int jTime;
    int level = atoi(argv[1]);
    Node* root = createNode();
    Node* rootNew = createNode();


    if (argc == 2) {
        level = 1;
        printf("调试等级1\n");
        strcpy(outerDns, DEF_DNS_ADDRESS);
        strcpy(tablePath, "D:\\DNS\\dnsrelay.txt");
    }

    else if (argc == 4) {
        level = 2;
        printf("调试等级2\n");
        strcpy(outerDns, argv[2]);
        strcpy(tablePath, argv[3]);
    }

    else if (argc == 3) {
        level = 3;
        printf("调试等级3\n");
        strcpy(outerDns, argv[2]);
        strcpy(tablePath, "D:\\DNS\\dnsrelay.txt");
    }

    num = GetTable(tablePath, root);
    mod = AMOUNT - num;


    GetLocalTime(&sys);
    Day = sys.wDay;
    Hour = sys.wHour;
    Min = sys.wMinute;
    Sec = sys.wSecond;
    Msec = sys.wMilliseconds;
    Day2 = sys.wDay;
    Hour2 = sys.wHour;
    Min2 = sys.wMinute;
    Sec2 = sys.wSecond;

    for (int i = 0; i < AMOUNT; i++) {
        IDTransTable[i].oldID = 0;
        IDTransTable[i].done = FALSE;
        IDTransTable[i].joinTime = 0;
        IDTransTable[i].offset = 0;
        memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
        memset(&(IDTransTable[i].urlName), 0, LENGTH * sizeof(char));
    }

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    socketServer = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned long u1 = 1;
    ioctlsocket(socketServer, FIONBIO, (unsigned long*)&u1);

    socketLocal = socket(AF_INET, SOCK_DGRAM, 0);


    localName.sin_family = AF_INET;
    localName.sin_port = htons(DNS_PORT);
    localName.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);

    serverName.sin_family = AF_INET;
    serverName.sin_port = htons(DNS_PORT);
    serverName.sin_addr.s_addr = inet_addr(outerDns);

    if (bind(socketLocal, (SOCKADDR*)&localName, sizeof(localName))) {
        printf("\n绑定53号端口失败");
        exit(1);
    }
    else {
        printf("\n绑定53号端口成功");
    }

    int find;
    int add;
    unsigned short NewID;
    unsigned short* pID;

    while (1) {
        number_level++;
        iLen_cli = sizeof(clientName);
        memset(recvbuf, 0, BUF_SIZE);

        iRecv = recvfrom(socketLocal, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);

        if (iRecv == SOCKET_ERROR)
        {
            continue;
        }
        else if (iRecv == 0)
        {
            break;
        }
        else
        {
            GetUrl(recvbuf, iRecv);

            int result = search(root, url);

            if(result == -1){
                //ID转换
                pID = (unsigned short*)malloc(sizeof(unsigned short*));
                memcpy(pID, recvbuf, sizeof(unsigned short));
                memcpy(idbuf, recvbuf, sizeof(unsigned short));
                NewID = htons(ReplaceNewID(ntohs(*pID), clientName, FALSE));
                memcpy(recvbuf, &NewID, sizeof(unsigned short));

                rcv_port = clientName.sin_port;

                len=iRecv;
                if(ISA(recvbuf)) {
                    DisplayInfo(ntohs(NewID), result, level);
                }

                iSend = sendto(socketServer, recvbuf, iRecv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
                if (iSend == SOCKET_ERROR)
                {
                    continue;
                }
                else if (iSend == 0)
                    break;

                free(pID);

                clock_t start, stop;
                double duration = 0;


                start = clock();
                iRecv = recvfrom(socketServer, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);
                while ((iRecv == 0) || (iRecv == SOCKET_ERROR))
                {
                    iRecv = recvfrom(socketServer, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);
                    stop = clock();
                    duration = (double)(stop - start) / CLK_TCK;
                    if (duration > 5)
                    {
                        printf("回应超时\n");
                        goto ps;
                    }
                }

                GetIP(recvbuf, iRecv);
                if(search(rootNew, url) == -1){
                    DNS_table[num + count].IP = nIP;
                    DNS_table[num + count].domain = url;
                    insert(root, DNS_table[num].domain, num + count);
                    count = (count + 1) % mod;
                }

                len=iRecv;
                if(ISA(recvbuf)) {
                    DisplayInfo(ntohs(NewID), -2, level);
                }

                pID = (unsigned short*)malloc(sizeof(unsigned short*));
                memcpy(pID, recvbuf, sizeof(unsigned short));
                int GetId = ntohs(*pID);
                unsigned short oID = htons(IDTransTable[GetId].oldID);
                memcpy(recvbuf, &oID, sizeof(unsigned short));
                IDTransTable[GetId].done = TRUE;

                rcv_port = clientName.sin_port;

                clientName = IDTransTable[GetId].client;

                iSend = sendto(socketLocal, recvbuf, iRecv, 0, (SOCKADDR*)&clientName, sizeof(clientName));
                if (iSend == SOCKET_ERROR)
                {
                    continue;
                }
                else if (iSend == 0)
                    break;

                free(pID);
            }

            else
            {

                pID = (unsigned short*)malloc(sizeof(unsigned short*));
                memcpy(pID, recvbuf, sizeof(unsigned short));

                unsigned short nID = ReplaceNewID(ntohs(*pID), clientName, TRUE);

                rcv_port = clientName.sin_port;

                len=iRecv;
                if(ISA(recvbuf)) {
                    DisplayInfo(ntohs(NewID), result, level);
                }

                memcpy(sendbuf, recvbuf, iRecv);
                unsigned short AFlag = htons(0x8180);
                memcpy(&sendbuf[2], &AFlag, sizeof(unsigned short));


                if (strcmp(DNS_table[result].IP, "0.0.0.0") == 0)
                    AFlag = htons(0x0000);
                else
                    AFlag = htons(0x0001);
                memcpy(&sendbuf[6], &AFlag, sizeof(unsigned short));

                int curLen = 0;


                char answer[16];
                unsigned short Name = htons(0xc00c);
                memcpy(answer, &Name, sizeof(unsigned short));
                curLen += sizeof(unsigned short);

                unsigned short TypeA = htons(0x0001);
                memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
                curLen += sizeof(unsigned short);

                unsigned short ClassA = htons(0x0001);
                memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
                curLen += sizeof(unsigned short);


                unsigned long timeLive = htonl(0x7b);
                memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
                curLen += sizeof(unsigned long);

                unsigned short RDLength = htons(0x0004);
                memcpy(answer + curLen, &RDLength, sizeof(unsigned short));
                curLen += sizeof(unsigned short);

                unsigned long IP;
                inet_pton(AF_INET, DNS_table[result].IP, &IP);
                memcpy(answer + curLen, &IP, sizeof(unsigned long));
                curLen += sizeof(unsigned long);
                curLen += iRecv;


                memcpy(sendbuf + iRecv, answer, curLen);

                clock_t Nstart, Nstop;
                double Nduration;


                Nstart = clock();
                iSend = sendto(socketLocal, sendbuf, curLen, 0, (SOCKADDR*)&clientName, sizeof(clientName));

                free(pID);
            }
        }
        ps:;
    }
    closesocket(socketServer);
    closesocket(socketLocal);
    WSACleanup();

    system("pause");
    printf("\n\n程序停止");
    return 0;
}