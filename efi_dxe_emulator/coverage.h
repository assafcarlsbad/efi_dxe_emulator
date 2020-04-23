#pragma once

#include <unicorn/unicorn.h>

void register_coverage_cmds(uc_engine* uc);
void record_basic_block(uc_engine *uc, uint64_t address, uint32_t size);
void dump_coverage(const char* coverage_file);