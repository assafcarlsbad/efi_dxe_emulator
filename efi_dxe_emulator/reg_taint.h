#pragma once

#include <capstone/capstone.h>

bool taint_reg(x86_reg reg);
bool untaint_reg(x86_reg reg);
bool is_reg_tainted(x86_reg reg);