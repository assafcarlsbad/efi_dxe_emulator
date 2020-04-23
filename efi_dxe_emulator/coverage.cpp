#include "loader.h"
#include <vector>
#include <sstream>
#include "logging.h"
#include "string_ops.h"
#include <capstone/capstone.h>
#include "capstone_utils.h"
#include <array>
#include "cmds.h"

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
        bool stop = false;
        while (!stop && get_instruction(uc, bb_end, &insn) == 0)
        {
            for (uint32_t i = 0; i < insn->detail->groups_count; i++)
            {
                if (insn->detail->groups[i] == X86_GRP_CALL)
                {
                    stop = true;
                    break;
                }
            }

            bb_end += insn->size;
            cs_free(insn, 1);
        }

        size = bb_end - address;
    }

    return size;
}

static bool coverage_on = false;

static int
coverage_cmd(const char* exp, uc_engine* uc)
{
    auto tokens = tokenize(exp);

    std::string verb;
    try
    {
        verb = tokens.at(1);
    }
    catch (const std::out_of_range&)
    {
        ERROR_MSG("Usage: cov [start|stop]");
        return 0;
    }

    if (verb == "start")
    {
        OUTPUT_MSG("[+] Starting code coverage collection");
        coverage_on = true;
    }
    else if (verb == "stop")
    {
        OUTPUT_MSG("[+] Stopping code coverage collection");
        coverage_on = false;
    }
    else
    {
        ERROR_MSG("Usage: cov [start|stop]");
    }

    return 0;
}

void
register_coverage_cmds(uc_engine *uc)
{
    add_user_cmd("coverage", "cov", coverage_cmd, "Controls coverage collection.\n\ncov [start|stop]", uc);
}

void record_basic_block(uc_engine *uc, uint64_t address, uint32_t size)
{
    /* For now always record code coverage unconditionally, otherwise we'll "miss"
     * the first block of the entrypoint. Remove this comment once the issue is fixed */
    //if (!coverage_on) return;

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
            basic_blocks.push_back(bb);
            break;
        }

        mod_id++;
    }
}

void dump_coverage(const char* coverage_file)
{
    /* See https://www.ayrx.me/drcov-file-format for a more detailed explanation */
    std::stringstream drcov_header;
    drcov_header << "DRCOV VERSION: " << 2 << std::endl;
    drcov_header << "DRCOV FLAVOR: " << "drcov" << std::endl;
    drcov_header << "Module Table: " << "version " << 2 << ", count " << 1 << std::endl;
    drcov_header << "Columns: id, base, end, entry, checksum, timestamp, path" << std::endl;

    struct bin_image* current_image = NULL;
    uint16_t mod_id = 0;
    TAILQ_FOREACH(current_image, &g_images, entries)
    {
        drcov_header << mod_id << ", "
                     << current_image->base_addr << ", "
                     << current_image->base_addr + current_image->buf_size << ", "
                     << 0 << ", "
                     << 0 << ", "
                     << 0 << ", "
                     << current_image->file_path
                     << std::endl;
        mod_id++;
    }
    drcov_header << "BB Table: " << basic_blocks.size() << " bbs" << std::endl;
    
    FILE *fp = fopen(coverage_file, "wb");
    fwrite(drcov_header.str().c_str(), 1, drcov_header.str().length(), fp);
    fwrite(basic_blocks.data(), sizeof(bb_entry_t), basic_blocks.size(), fp);
    fclose(fp);
}