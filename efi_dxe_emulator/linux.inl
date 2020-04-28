#pragma once

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

typedef __builtin_va_list VA_LIST;
