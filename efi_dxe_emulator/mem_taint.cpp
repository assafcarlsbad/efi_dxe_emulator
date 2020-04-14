#include "mem_taint.h"
#include "logging.h"

#include <set>

std::set<uint64_t> tainted_addresses;

bool taint_mem(uint64_t address)
{
    auto [_, tainted] = tainted_addresses.insert(address);
    return tainted;
}

bool taint_mem(uint64_t address, uint8_t size)
{
    bool tainted = false;
    for (uint8_t i = 0; i < size; i++)
    {
        tainted |= taint_mem(address + i);
    }

    if (tainted)
    {
        TAINT_MSG("Tainting memory range 0x%llx-0x%llx", address, address + size);
        return true;
    }

    return false;
}

bool untaint_mem(uint64_t address)
{
    size_t erased = tainted_addresses.erase(address);
    return (erased > 0);
}

bool untaint_mem(uint64_t address, uint8_t size)
{
    bool erased = false;
    for (uint8_t i = 0; i < size; i++)
    {
        erased |= untaint_mem(address + i);
    }

    if (erased)
    {
        TAINT_MSG("Un-tainted memory range 0x%llx-0x%llx", address, address + size);
        return true;
    }

    return false;
}

bool is_mem_tainted(uint64_t address)
{
    return (tainted_addresses.find(address) != tainted_addresses.end());
}

bool is_mem_tainted(uint64_t address, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
    {
        if (is_mem_tainted(address + i))
        {
            return true;
        }
    }
    return false;
}