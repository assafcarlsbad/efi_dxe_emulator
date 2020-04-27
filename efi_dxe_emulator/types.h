#pragma once

#ifdef _WIN32

#else
typedef struct _LIST_ENTRY LIST_ENTRY;

struct _LIST_ENTRY {
    LIST_ENTRY* ForwardLink;
    LIST_ENTRY* BackLink;
};
#endif // _WIN32