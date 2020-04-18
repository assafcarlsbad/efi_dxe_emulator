#include "reg_taint.h"
#include "logging.h"
#include "capstone_utils.h"

#include <capstone/capstone.h>
#include <set>

std::set<x86_reg> tainted_regs;

bool _taint_reg(x86_reg reg)
{
    auto [_, tainted] = tainted_regs.insert(reg);
    return tainted;
}

bool taint_reg(x86_reg reg)
{
    bool tainted = false;

    switch (reg)
    {
    case X86_REG_RAX:  tainted |= _taint_reg(X86_REG_RAX);
    case X86_REG_EAX:  tainted |= _taint_reg(X86_REG_EAX);
    case X86_REG_AX:   tainted |= _taint_reg(X86_REG_AX);
    case X86_REG_AH:   tainted |= _taint_reg(X86_REG_AH);
    case X86_REG_AL:   tainted |= _taint_reg(X86_REG_AL);
        break;

    case X86_REG_RBX:  tainted |= _taint_reg(X86_REG_RBX);
    case X86_REG_EBX:  tainted |= _taint_reg(X86_REG_EBX);
    case X86_REG_BX:   tainted |= _taint_reg(X86_REG_BX);
    case X86_REG_BH:   tainted |= _taint_reg(X86_REG_BH);
    case X86_REG_BL:   tainted |= _taint_reg(X86_REG_BL);
        break;

    case X86_REG_RCX:  tainted |= _taint_reg(X86_REG_RCX);
    case X86_REG_ECX:  tainted |= _taint_reg(X86_REG_ECX);
    case X86_REG_CX:   tainted |= _taint_reg(X86_REG_CX);
    case X86_REG_CH:   tainted |= _taint_reg(X86_REG_CH);
    case X86_REG_CL:   tainted |= _taint_reg(X86_REG_CL);
        break;

    case X86_REG_RDX:  tainted |= _taint_reg(X86_REG_RDX);
    case X86_REG_EDX:  tainted |= _taint_reg(X86_REG_EDX);
    case X86_REG_DX:   tainted |= _taint_reg(X86_REG_DX);
    case X86_REG_DH:   tainted |= _taint_reg(X86_REG_DH);
    case X86_REG_DL:   tainted |= _taint_reg(X86_REG_DL);
        break;

    case X86_REG_RDI:  tainted |= _taint_reg(X86_REG_RDI);
    case X86_REG_EDI:  tainted |= _taint_reg(X86_REG_EDI);
    case X86_REG_DI:   tainted |= _taint_reg(X86_REG_DI);
    case X86_REG_DIL:  tainted |= _taint_reg(X86_REG_DIL);
        break;

    case X86_REG_RBP:  tainted |= _taint_reg(X86_REG_RBP);
    case X86_REG_EBP:  tainted |= _taint_reg(X86_REG_EBP);
    case X86_REG_BP:   tainted |= _taint_reg(X86_REG_BP);
    case X86_REG_BPL:  tainted |= _taint_reg(X86_REG_BPL);
        break;

    case X86_REG_RSI:  tainted |= _taint_reg(X86_REG_RSI);
    case X86_REG_ESI:  tainted |= _taint_reg(X86_REG_ESI);
    case X86_REG_SI:   tainted |= _taint_reg(X86_REG_SI);
    case X86_REG_SIL:  tainted |= _taint_reg(X86_REG_SIL);
        break;

    case X86_REG_R8:   tainted |= _taint_reg(X86_REG_R8);
    case X86_REG_R8D:  tainted |= _taint_reg(X86_REG_R8D);
    case X86_REG_R8W:  tainted |= _taint_reg(X86_REG_R8W);
    case X86_REG_R8B:  tainted |= _taint_reg(X86_REG_R8B);
        break;

    case X86_REG_R9:   tainted |= _taint_reg(X86_REG_R9);
    case X86_REG_R9D:  tainted |= _taint_reg(X86_REG_R9D);
    case X86_REG_R9W:  tainted |= _taint_reg(X86_REG_R9W);
    case X86_REG_R9B:  tainted |= _taint_reg(X86_REG_R9B);
        break;

    case X86_REG_R10:   tainted |= _taint_reg(X86_REG_R10);
    case X86_REG_R10D:  tainted |= _taint_reg(X86_REG_R10D);
    case X86_REG_R10W:  tainted |= _taint_reg(X86_REG_R10W);
    case X86_REG_R10B:  tainted |= _taint_reg(X86_REG_R10B);
        break;

    case X86_REG_R11:   tainted |= _taint_reg(X86_REG_R11);
    case X86_REG_R11D:  tainted |= _taint_reg(X86_REG_R11D);
    case X86_REG_R11W:  tainted |= _taint_reg(X86_REG_R11W);
    case X86_REG_R11B:  tainted |= _taint_reg(X86_REG_R11B);
        break;

    case X86_REG_R12:   tainted |= _taint_reg(X86_REG_R12);
    case X86_REG_R12D:  tainted |= _taint_reg(X86_REG_R12D);
    case X86_REG_R12W:  tainted |= _taint_reg(X86_REG_R12W);
    case X86_REG_R12B:  tainted |= _taint_reg(X86_REG_R12B);
        break;

    case X86_REG_R13:   tainted |= _taint_reg(X86_REG_R13);
    case X86_REG_R13D:  tainted |= _taint_reg(X86_REG_R13D);
    case X86_REG_R13W:  tainted |= _taint_reg(X86_REG_R13W);
    case X86_REG_R13B:  tainted |= _taint_reg(X86_REG_R13B);
        break;

    case X86_REG_R14:   tainted |= _taint_reg(X86_REG_R14);
    case X86_REG_R14D:  tainted |= _taint_reg(X86_REG_R14D);
    case X86_REG_R14W:  tainted |= _taint_reg(X86_REG_R14W);
    case X86_REG_R14B:  tainted |= _taint_reg(X86_REG_R14B);
        break;

    case X86_REG_R15:   tainted |= _taint_reg(X86_REG_R15);
    case X86_REG_R15D:  tainted |= _taint_reg(X86_REG_R15D);
    case X86_REG_R15W:  tainted |= _taint_reg(X86_REG_R15W);
    case X86_REG_R15B:  tainted |= _taint_reg(X86_REG_R15B);
        break;

    default:
        ERROR_MSG("Register %s can't be tainted", get_register_name(reg));
        return false;
    }

    if (tainted)
    {
        TAINT_MSG("Tainting register %s", get_register_name(reg));
        return true;
    }

    return false;
}


bool untaint_reg(x86_reg reg)
{
    size_t removed = 0;

    switch (reg)
    {
    case X86_REG_RAX:  removed += tainted_regs.erase(X86_REG_RAX);
    case X86_REG_EAX:  removed += tainted_regs.erase(X86_REG_EAX);
    case X86_REG_AX:   removed += tainted_regs.erase(X86_REG_AX);
    case X86_REG_AH:   removed += tainted_regs.erase(X86_REG_AH);
    case X86_REG_AL:   removed += tainted_regs.erase(X86_REG_AL);
        break;

    case X86_REG_RBX:  removed += tainted_regs.erase(X86_REG_RBX);
    case X86_REG_EBX:  removed += tainted_regs.erase(X86_REG_EBX);
    case X86_REG_BX:   removed += tainted_regs.erase(X86_REG_BX);
    case X86_REG_BH:   removed += tainted_regs.erase(X86_REG_BH);
    case X86_REG_BL:   removed += tainted_regs.erase(X86_REG_BL);
        break;

    case X86_REG_RCX:  removed += tainted_regs.erase(X86_REG_RCX);
    case X86_REG_ECX:  removed += tainted_regs.erase(X86_REG_ECX);
    case X86_REG_CX:   removed += tainted_regs.erase(X86_REG_CX);
    case X86_REG_CH:   removed += tainted_regs.erase(X86_REG_CH);
    case X86_REG_CL:   removed += tainted_regs.erase(X86_REG_CL);
        break;

    case X86_REG_RDX:  removed += tainted_regs.erase(X86_REG_RDX);
    case X86_REG_EDX:  removed += tainted_regs.erase(X86_REG_EDX);
    case X86_REG_DX:   removed += tainted_regs.erase(X86_REG_DX);
    case X86_REG_DH:   removed += tainted_regs.erase(X86_REG_DH);
    case X86_REG_DL:   removed += tainted_regs.erase(X86_REG_DL);
        break;

    case X86_REG_RDI:  removed += tainted_regs.erase(X86_REG_RDI);
    case X86_REG_EDI:  removed += tainted_regs.erase(X86_REG_EDI);
    case X86_REG_DI:   removed += tainted_regs.erase(X86_REG_DI);
    case X86_REG_DIL:  removed += tainted_regs.erase(X86_REG_DIL);
        break;

    case X86_REG_RSI:  removed += tainted_regs.erase(X86_REG_RSI);
    case X86_REG_ESI:  removed += tainted_regs.erase(X86_REG_ESI);
    case X86_REG_SI:   removed += tainted_regs.erase(X86_REG_SI);
    case X86_REG_SIL:  removed += tainted_regs.erase(X86_REG_SIL);
        break;

    case X86_REG_RSP:  removed += tainted_regs.erase(X86_REG_RSP);
    case X86_REG_ESP:  removed += tainted_regs.erase(X86_REG_ESP);
    case X86_REG_SP:   removed += tainted_regs.erase(X86_REG_SP);
    case X86_REG_SPL:  removed += tainted_regs.erase(X86_REG_SPL);
        break;

    case X86_REG_RBP:  removed += tainted_regs.erase(X86_REG_RBP);
    case X86_REG_EBP:  removed += tainted_regs.erase(X86_REG_EBP);
    case X86_REG_BP:   removed += tainted_regs.erase(X86_REG_BP);
    case X86_REG_BPL:  removed += tainted_regs.erase(X86_REG_BPL);
        break;

    case X86_REG_R8:   removed += tainted_regs.erase(X86_REG_R8);
    case X86_REG_R8D:  removed += tainted_regs.erase(X86_REG_R8D);
    case X86_REG_R8W:  removed += tainted_regs.erase(X86_REG_R8W);
    case X86_REG_R8B:  removed += tainted_regs.erase(X86_REG_R8B);
        break;

    case X86_REG_R9:   removed += tainted_regs.erase(X86_REG_R9);
    case X86_REG_R9D:  removed += tainted_regs.erase(X86_REG_R9D);
    case X86_REG_R9W:  removed += tainted_regs.erase(X86_REG_R9W);
    case X86_REG_R9B:  removed += tainted_regs.erase(X86_REG_R9B);
        break;

    case X86_REG_R10:  removed += tainted_regs.erase(X86_REG_R10);
    case X86_REG_R10D: removed += tainted_regs.erase(X86_REG_R10D);
    case X86_REG_R10W: removed += tainted_regs.erase(X86_REG_R10W);
    case X86_REG_R10B: removed += tainted_regs.erase(X86_REG_R10B);
        break;

    case X86_REG_R11:  removed += tainted_regs.erase(X86_REG_R11);
    case X86_REG_R11D: removed += tainted_regs.erase(X86_REG_R11D);
    case X86_REG_R11W: removed += tainted_regs.erase(X86_REG_R11W);
    case X86_REG_R11B: removed += tainted_regs.erase(X86_REG_R11B);
        break;

    case X86_REG_R12:  removed += tainted_regs.erase(X86_REG_R12);
    case X86_REG_R12D: removed += tainted_regs.erase(X86_REG_R12D);
    case X86_REG_R12W: removed += tainted_regs.erase(X86_REG_R12W);
    case X86_REG_R12B: removed += tainted_regs.erase(X86_REG_R12B);
        break;

    case X86_REG_R13:  removed += tainted_regs.erase(X86_REG_R13);
    case X86_REG_R13D: removed += tainted_regs.erase(X86_REG_R13D);
    case X86_REG_R13W: removed += tainted_regs.erase(X86_REG_R13W);
    case X86_REG_R13B: removed += tainted_regs.erase(X86_REG_R13B);
        break;

    case X86_REG_R14:  removed += tainted_regs.erase(X86_REG_R14);
    case X86_REG_R14D: removed += tainted_regs.erase(X86_REG_R14D);
    case X86_REG_R14W: removed += tainted_regs.erase(X86_REG_R14W);
    case X86_REG_R14B: removed += tainted_regs.erase(X86_REG_R14B);
        break;

    case X86_REG_R15:  removed += tainted_regs.erase(X86_REG_R15);
    case X86_REG_R15D: removed += tainted_regs.erase(X86_REG_R15D);
    case X86_REG_R15W: removed += tainted_regs.erase(X86_REG_R15W);
    case X86_REG_R15B: removed += tainted_regs.erase(X86_REG_R15B);
        break;

    default:
        ERROR_MSG("Don't know how to untaint register %s", get_register_name(reg));
        return false;
    }

    if (removed > 0)
    {
        TAINT_MSG("Un-tainting register %s", get_register_name(reg));
        return true;
    }
    return false;
}

bool _is_reg_tainted(x86_reg reg)
{
    return (tainted_regs.find(reg) != tainted_regs.end());
}

bool is_reg_tainted(x86_reg reg)
{
    std::set<x86_reg> partial_regs;

    switch (reg)
    {
    case X86_REG_RAX:  partial_regs.insert(X86_REG_RAX);
    case X86_REG_EAX:  partial_regs.insert(X86_REG_EAX);
    case X86_REG_AX:   partial_regs.insert(X86_REG_AX);
    case X86_REG_AH:   partial_regs.insert(X86_REG_AH);
    case X86_REG_AL:   partial_regs.insert(X86_REG_AL);
        break;

    case X86_REG_RBX:  partial_regs.insert(X86_REG_RBX);
    case X86_REG_EBX:  partial_regs.insert(X86_REG_EBX);
    case X86_REG_BX:   partial_regs.insert(X86_REG_BX);
    case X86_REG_BH:   partial_regs.insert(X86_REG_BH);
    case X86_REG_BL:   partial_regs.insert(X86_REG_BL);
        break;

    case X86_REG_RCX:  partial_regs.insert(X86_REG_RCX);
    case X86_REG_ECX:  partial_regs.insert(X86_REG_ECX);
    case X86_REG_CX:   partial_regs.insert(X86_REG_CX);
    case X86_REG_CH:   partial_regs.insert(X86_REG_CH);
    case X86_REG_CL:   partial_regs.insert(X86_REG_CL);
        break;

    case X86_REG_RDX:  partial_regs.insert(X86_REG_RDX);
    case X86_REG_EDX:  partial_regs.insert(X86_REG_EDX);
    case X86_REG_DX:   partial_regs.insert(X86_REG_DX);
    case X86_REG_DH:   partial_regs.insert(X86_REG_DH);
    case X86_REG_DL:   partial_regs.insert(X86_REG_DL);
        break;

    case X86_REG_RDI:  partial_regs.insert(X86_REG_RDI);
    case X86_REG_EDI:  partial_regs.insert(X86_REG_EDI);
    case X86_REG_DI:   partial_regs.insert(X86_REG_DI);
    case X86_REG_DIL:  partial_regs.insert(X86_REG_DIL);
        break;

    case X86_REG_RSI:  partial_regs.insert(X86_REG_RSI);
    case X86_REG_ESI:  partial_regs.insert(X86_REG_ESI);
    case X86_REG_SI:   partial_regs.insert(X86_REG_SI);
    case X86_REG_SIL:  partial_regs.insert(X86_REG_SIL);
        break;

    case X86_REG_RBP:  partial_regs.insert(X86_REG_RBP);
    case X86_REG_EBP:  partial_regs.insert(X86_REG_EBP);
    case X86_REG_BP:   partial_regs.insert(X86_REG_BP);
    case X86_REG_BPL:  partial_regs.insert(X86_REG_BPL);
        break;

    case X86_REG_RSP:  partial_regs.insert(X86_REG_RSP);
    case X86_REG_ESP:  partial_regs.insert(X86_REG_ESP);
    case X86_REG_SP:   partial_regs.insert(X86_REG_SP);
    case X86_REG_SPL:  partial_regs.insert(X86_REG_SPL);
        break;

    case X86_REG_R8:   partial_regs.insert(X86_REG_R8);
    case X86_REG_R8D:  partial_regs.insert(X86_REG_R8D);
    case X86_REG_R8W:  partial_regs.insert(X86_REG_R8W);
    case X86_REG_R8B:  partial_regs.insert(X86_REG_R8B);
        break;

    case X86_REG_R9:   partial_regs.insert(X86_REG_R9);
    case X86_REG_R9D:  partial_regs.insert(X86_REG_R9D);
    case X86_REG_R9W:  partial_regs.insert(X86_REG_R9W);
    case X86_REG_R9B:  partial_regs.insert(X86_REG_R9B);
        break;

    case X86_REG_R10:   partial_regs.insert(X86_REG_R10);
    case X86_REG_R10D:  partial_regs.insert(X86_REG_R10D);
    case X86_REG_R10W:  partial_regs.insert(X86_REG_R10W);
    case X86_REG_R10B:  partial_regs.insert(X86_REG_R10B);
        break;

    case X86_REG_R11:   partial_regs.insert(X86_REG_R11);
    case X86_REG_R11D:  partial_regs.insert(X86_REG_R11D);
    case X86_REG_R11W:  partial_regs.insert(X86_REG_R11W);
    case X86_REG_R11B:  partial_regs.insert(X86_REG_R11B);
        break;

    case X86_REG_R12:   partial_regs.insert(X86_REG_R12);
    case X86_REG_R12D:  partial_regs.insert(X86_REG_R12D);
    case X86_REG_R12W:  partial_regs.insert(X86_REG_R12W);
    case X86_REG_R12B:  partial_regs.insert(X86_REG_R12B);
        break;

    case X86_REG_R13:   partial_regs.insert(X86_REG_R13);
    case X86_REG_R13D:  partial_regs.insert(X86_REG_R13D);
    case X86_REG_R13W:  partial_regs.insert(X86_REG_R13W);
    case X86_REG_R13B:  partial_regs.insert(X86_REG_R13B);
        break;

    case X86_REG_R14:   partial_regs.insert(X86_REG_R14);
    case X86_REG_R14D:  partial_regs.insert(X86_REG_R14D);
    case X86_REG_R14W:  partial_regs.insert(X86_REG_R14W);
    case X86_REG_R14B:  partial_regs.insert(X86_REG_R14B);
        break;

    case X86_REG_R15:   partial_regs.insert(X86_REG_R15);
    case X86_REG_R15D:  partial_regs.insert(X86_REG_R15D);
    case X86_REG_R15W:  partial_regs.insert(X86_REG_R15W);
    case X86_REG_R15B:  partial_regs.insert(X86_REG_R15B);
        break;

    default:
        ERROR_MSG("Unknown register %s", get_register_name(reg));
        return false;
    }

    for (const auto& candidate : partial_regs)
    {
        if (_is_reg_tainted(candidate))
        {
            return true;
        }
    }
    return false;
}
