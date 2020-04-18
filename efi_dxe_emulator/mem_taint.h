#pragma once

#include <stdint.h>


bool taint_mem(uint64_t address);
bool taint_mem(uint64_t address, uint32_t size);

bool untaint_mem(uint64_t address, uint32_t size);

bool is_mem_tainted(uint64_t address);
bool is_mem_tainted(uint64_t address, uint32_t size);
