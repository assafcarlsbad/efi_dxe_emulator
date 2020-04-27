#pragma once

#ifdef _WIN32
#ifndef GUID_DEFINED
#include <guiddef.h>
#endif // !GUID_DEFINED
#else
typedef struct _LIST_ENTRY LIST_ENTRY;

struct _LIST_ENTRY {
    LIST_ENTRY* ForwardLink;
    LIST_ENTRY* BackLink;
};

typedef void VOID;

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;
#endif // _WIN32
