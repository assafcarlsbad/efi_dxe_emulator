#include "taint.h"
#include "mem_taint.h"
#include "reg_taint.h"
#include "capstone_utils.h"
#include "logging.h"

static bool propagate_taint_m2r(uint64_t address, uint8_t size, x86_reg reg);
static bool propagate_taint_r2r(x86_reg reg1, x86_reg reg2);
static bool propagate_taint_r2m(x86_reg reg, uint64_t address, uint8_t size);

bool propagate_taint_m2r(uint64_t address, uint8_t size, x86_reg reg)
{
    if (is_mem_tainted(address, size))
    {
        return taint_reg(reg);
    }
    else
    {
        return untaint_reg(reg);
    }
}

bool propagate_taint_r2r(x86_reg reg1, x86_reg reg2)
{
    if (is_reg_tainted(reg1))
    {
        return taint_reg(reg2);
    }
    else
    {
        return untaint_reg(reg2);
    }
}

bool propagate_taint_r2m(x86_reg reg, uint64_t address, uint8_t size)
{
    if (is_reg_tainted(reg))
    {
        return taint_mem(address, size);
    }
    else
    {
        return untaint_mem(address, size);
    }
}

void propagate_taint(uc_engine* uc, cs_insn* insn)
{
    if (insn->detail->x86.op_count < 2)
    {
        return;
    }

    const auto& dst_opnd = insn->detail->x86.operands[0];
    const auto& src_opnd = insn->detail->x86.operands[1];

    bool taint_modified = false;

    if ((dst_opnd.type == X86_OP_REG) && (dst_opnd.access == CS_AC_WRITE) &&
        (src_opnd.type == X86_OP_MEM) && (src_opnd.access == CS_AC_READ))
    {
        /* CASE 1: memory to register */
        uint64_t address = retrieve_effetive_address(uc, src_opnd.mem);
        taint_modified = propagate_taint_m2r(address, src_opnd.size, dst_opnd.reg);
    }
    else if ((dst_opnd.type == X86_OP_REG) && (dst_opnd.access == CS_AC_WRITE) &&
             (src_opnd.type == X86_OP_REG) && (src_opnd.access == CS_AC_READ))
    {
        /* CASE 2: register to register */
        taint_modified = propagate_taint_r2r(src_opnd.reg, dst_opnd.reg);
    }
    else if ((dst_opnd.type == X86_OP_MEM) && (dst_opnd.access == CS_AC_WRITE) &&
             (src_opnd.type == X86_OP_REG) && (src_opnd.access == CS_AC_READ))
    {
        /* CASE 3: register to memory */
        uint64_t address = retrieve_effetive_address(uc, dst_opnd.mem);
        taint_modified = propagate_taint_r2m(src_opnd.reg, address, dst_opnd.size);
    }

    if (taint_modified)
    {
        DEBUG_MSG("INSTRUCTION: %s %s", insn->mnemonic, insn->op_str);
    }
}
