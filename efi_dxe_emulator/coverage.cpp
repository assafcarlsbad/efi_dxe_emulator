#include "loader.h"
#include <vector>
#include <sstream>
#include "logging.h"
#include "string_ops.h"
#include <capstone/capstone.h>
#include "capstone_utils.h"
#include <array>

extern struct bin_images_tailq g_images;

/* Taken from https://www.ayrx.me/drcov-file-format */
typedef struct _bb_entry_t
{
    uint32_t start;
    uint16_t size;
    uint16_t mod_id;
} bb_entry_t;

std::vector<bb_entry_t> basic_blocks;

static uint32_t
block_size_workaround(uc_engine* uc, uint64_t address, uint32_t size)
{
    if (size == 0)
    {
        /* Looks like a Unicorn bug: in some cases the block's size is reported as 0.
         * As a walkaround, we'll disassemble the code until we reach a 'CALL' instruction
         * and compute the size accordingly. */
        uint64_t bb_end = address;
        cs_insn* insn = nullptr;
        while (get_instruction(uc, bb_end, &insn) == 0)
        {
            if (strcmp(insn->mnemonic, "call") == 0)
            {
                cs_free(insn, 1);
                break;
            }

            bb_end += insn->size;
            cs_free(insn, 1);
        }

        size = bb_end - address;
    }

    return size;
}

void record_basic_block(uc_engine *uc, uint64_t address, uint32_t size)
{
    size = block_size_workaround(uc, address, size);

    struct bin_image* current_image = NULL;
    uint16_t mod_id = 0;
    TAILQ_FOREACH(current_image, &g_images, entries)
    {
        if ((current_image->mapped_addr <= address) &&
            (address <= current_image->mapped_addr + current_image->buf_size))
        {
            bb_entry_t bb;
            bb.mod_id = mod_id;
            bb.size = size;
            bb.start = address - current_image->mapped_addr;
            //OUTPUT_MSG("Start = 0x%lx, size = 0x%x", bb.start, bb.size);
            basic_blocks.push_back(bb);
            break;
        }

        mod_id++;
    }
}

void finalize_coverage(const char* coverage_file)
{
    /* See https://www.ayrx.me/drcov-file-format for a more detailed explanation */
    std::stringstream ss;
    ss << "DRCOV VERSION: " << 2 << std::endl;
    ss << "DRCOV FLAVOR: " << "drcov" << std::endl;
    ss << "Module Table: " << "version " << 2 << ", count " << 1 << std::endl;
    ss << "Columns: id, base, end, entry, checksum, timestamp, path" << std::endl;

    struct bin_image* current_image = NULL;
    uint16_t mod_id = 0;
    TAILQ_FOREACH(current_image, &g_images, entries)
    {
        ss << mod_id << ", "
           << current_image->base_addr << ", "
           << current_image->base_addr + current_image->buf_size << ", "
           << 0 << ", "
           << 0 << ", "
           << 0 << ", "
           << current_image->file_path
           << std::endl;
        mod_id++;
    }
    ss << "BB Table: " << basic_blocks.size() << " bbs" << std::endl;
    
    FILE *fp = fopen(coverage_file, "wb");
    fwrite(ss.str().c_str(), 1, ss.str().length(), fp);
    fwrite(basic_blocks.data(), sizeof(bb_entry_t), basic_blocks.size(), fp);
    fclose(fp);
}