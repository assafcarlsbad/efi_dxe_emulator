#pragma once

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

void propagate_taint(uc_engine *uc, cs_insn* insn);