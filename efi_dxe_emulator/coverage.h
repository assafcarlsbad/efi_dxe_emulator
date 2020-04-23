#pragma once

#include <stdint.h>

void on_basic_block(uc_engine *uc, uint64_t address, uint32_t size);
void finalize_coverage(const char* coverage_file);