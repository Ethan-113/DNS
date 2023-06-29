#ifndef DEFINITION_H_INCLUDED
#define DEFINITION_H_INCLUDED

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <windows.h>
#include <time.h>

#define DEF_DNS_ADDRESS "10.3.9.45"
#define LOCAL_ADDRESS "10.28.227.44"
#define DNS_PORT 53
#define BUF_SIZE 1024
#define LENGTH 65
#define AMOUNT 1500
#define NOTFOUND -1
#define FOUND 1
#define ALPHABET_SIZE 38


typedef struct DNSHeader
{
    unsigned short ID;
    unsigned short Flags;
    unsigned short QuestNum;
    unsigned short AnswerNum;
    unsigned short AuthorNum;
    unsigned short AdditionNum;
} DNSHDR, * pDNSHDR;

struct DNSQuestion {
    unsigned short qtype;
    unsigned short qclass;
};


struct DNSAnswer {
    unsigned short name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
};

typedef struct
{
    char addr[16];
} ip_addr;


typedef struct translate
{
    char* IP;
    char* domain;
} Translate;

//ID转换表结构
typedef struct IDChange
{
    unsigned short oldID;
    BOOL done;
    SOCKADDR_IN client;
    int joinTime;
    char urlName[LENGTH];
    int offset;
} IDTransform;

typedef struct trieNode {
    struct trieNode* children[ALPHABET_SIZE];
    int count;
} Node, * pNode;

#endif // !DEFINITION_H_INCLUDED
