#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <mman/sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
//#include <filesystem>
#include "loader.h"
#include <unicorn/unicorn.h>

//#include <linenoise.h>
//#include "ini.h"

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
//#include "debugger.h"
//#include "cmds.h"
//#include "global_cmds.h"
//#include "breakpoints.h"
#include "loader.h"
#include "unicorn_hooks.h"
//#include "protocols.h"
#include "unicorn_macros.h"
#include "unicorn_utils.h"
#include "mem_utils.h"
//#include "guids.h"

extern struct bin_images_tailq g_images;
struct configuration g_config;

void
header(void)
{
    printf(
        " ___ ___ ___   _____  _____   ___           _      _\n"
        "| __| __|_ _| |   \\ \\/ / __| | __|_ __ _  _| |__ _| |_ ___ _ _\n"
        "| _|| _| | |  | |) >  <| _|  | _|| '  \\ || | / _` |  _/ _ \\ '_|\n"
        "|___|_| |___| |___/_/\\_\\___| |___|_|_|_\\_,_|_\\__,_|\\__\\___/_|\n"
        "(c) 2016-2019, fG! - reverser@put.as - https://reverse.put.as\n\n"
        "A Unicorn Engine based EFI DXE binaries emulator and debugger\n\n"
    );
}

struct unicorn_hooks
{
    TAILQ_ENTRY(unicorn_hooks) entries;
    uc_hook hook;
    uint64_t begin;
    uint64_t end;
    int type;
};

TAILQ_HEAD(unicorn_hooks_tailq, unicorn_hooks);

struct unicorn_hooks_tailq g_hooks = TAILQ_HEAD_INITIALIZER(g_hooks);

/*
 * helper function to add a new Unicorn hook and bookkeep hooks in our internal structure
 *
 */
int
add_unicorn_hook(uc_engine* uc, int type, void* callback, uint64_t begin, uint64_t end)
{
    struct unicorn_hooks* new_hook = NULL;
    new_hook = static_cast<struct unicorn_hooks*>(my_malloc(sizeof(struct unicorn_hooks)));
    new_hook->begin = begin;
    new_hook->end = end;
    new_hook->type = type;

    if (uc_hook_add(uc, &new_hook->hook, type, callback, NULL, begin, end) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to add Unicorn hook.");
        free(new_hook);
        return 1;
    }

    TAILQ_INSERT_TAIL(&g_hooks, new_hook, entries);

    return 0;
}

void
help(const char* name)
{
    printf("\n---[ Usage: ]---\n"
        "%s -i ini file [-t EFI binary to emulate -n extracted NVRAM file from UEFITool] [-v]\n\n"
        "Where:\n"
        "-i ini file: path to ini file with emulation configuration\n\n"
        "-v: verbose logging\n"
        "Use these if no ini file is specified\n"
        "-t EFI binary: EFI binary to emulate\n"
        "-n nvram file: path to NVRAM file extracted by UEFITool\n"
        "", name);
}

void
hook_interrupt(uc_engine* uc, uint32_t intno, void* user_data)
{
    DEBUG_MSG("Hit interrupt nr %d", intno);
    uint64_t r_rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    uint64_t backtrace = 0;
    uc_mem_read(uc, r_rsp, &backtrace, sizeof(backtrace));
    DEBUG_MSG("Backtrace 0x%llx", backtrace);
    uint64_t r_rip = backtrace;
    uc_reg_write(uc, UC_X86_REG_RIP, &r_rip);
}

void
hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    DEBUG_MSG("Hit code at 0x%llx", address);
}

bool
hook_unmapped_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    switch (type) {
    case UC_MEM_READ_UNMAPPED:
        ERROR_MSG("Read from invalid memory at 0x%llx, data size = %u", address, size);
        break;
    case UC_MEM_WRITE_UNMAPPED:
        ERROR_MSG("Write to invalid memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
        break;
    case UC_MEM_FETCH_PROT:
        ERROR_MSG("Fetch from non-executable memory at 0x%llx", address);
        break;
    case UC_MEM_WRITE_PROT:
        ERROR_MSG("Write to non-writeable memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
        break;
    case UC_MEM_READ_PROT:
        ERROR_MSG("Read from non-readable memory at 0x%llx, data size = %u", address, size);
        break;
    default:
        ERROR_MSG("UC_HOOK_MEM_INVALID type: %d at 0x%llx", type, address);
        break;
    }
    DEBUG_MSG("Unmapped mem hit 0x%llx", address);
    return 0;
}

int
main(int argc, const char* argv[])
{
    header();

    // required structure for long options
    static struct option long_options[] = {
        { "verbose", no_argument, NULL, 'v' },
        { "target", required_argument, NULL, 't' },
        { "ini", required_argument, NULL, 'i' },
        { "nvram", required_argument, NULL, 'n' },
        { "guids", required_argument, NULL, 'g' },
        { "hexedit", required_argument, NULL, 'x' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    int c = 0;

    char* target_file = NULL;
    char* nvram_file = NULL;
    char* guids_file = NULL;
    int verbose_mode = 0;
    char* ini_file = NULL;
    char* hex_editor = NULL;

    // process command line options
    while ((c = getopt_long(argc, (char* const*)argv, "vt:n:g:i:x:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'v':
            verbose_mode = 1;
            break;
        case 't':
            target_file = optarg;
            break;
        case 'n':
            nvram_file = optarg;
            break;
        case 'g':
            guids_file = optarg;
            break;
        case 'i':
            ini_file = optarg;
            break;
        case 'x':
            hex_editor = optarg;
            break;
        default:
            break;
        }
    }

    set_log_level(verbose_mode);

    if (argc < 2)
    {
        help(argv[0]);
        return EXIT_FAILURE;
    }

    /* initialize the tailq that might hold protocols to load */
    TAILQ_INIT(&g_config.protos);

    /* explicit parameters should override the INI file */
    if (target_file) g_config.target_file = target_file;
    if (nvram_file) g_config.nvram_file = nvram_file;
    if (guids_file) g_config.guids_file = guids_file;
    if (hex_editor) g_config.hex_editor = hex_editor;

    if (g_config.target_file == NULL)
    {
        ERROR_MSG("Required target EFI file not found in ini file or command line arguments.");
        return EXIT_FAILURE;
    }
    if (g_config.nvram_file == NULL)
    {
        ERROR_MSG("Required NVRAM file not found in init file or command line arguments.");
        return EXIT_FAILURE;
    }

    /* use a default GUIDs file */
    if (g_config.guids_file == NULL)
    {
        g_config.guids_file = GUIDS_FILE;
    }

    if (g_config.hex_editor == NULL)
    {
        WARNING_MSG("Path to hex editor not specified, some commands will not work");
    }
    else
    {
        if (access(g_config.hex_editor, R_OK) < 0)
        {
            WARNING_MSG("Hex editor %s does not exit or not accessible. Error: %s.", g_config.hex_editor, strerror(errno));
        }
    }

    /* and now start the party */

    uc_engine* uc = NULL;
    uc_err err = UC_ERR_OK;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed on uc_open()");

    /* allocate the different memory areas for executables, stack, heap, efi services, etc */
    if (allocate_emulation_mem(uc) != 0)
    {
        ERROR_MSG("Failed to allocate Unicorn memory areas.");
        return EXIT_FAILURE;
    }

    OUTPUT_MSG("[+] Loading and mapping main EFI binary...");
    /* this is the main EFI binary we are going to emulate */
    if (load_and_map_main_image(g_config.target_file, uc) != 0)
    {
        ERROR_MSG("Failed to load main binary image.");
        return EXIT_FAILURE;
    }

    /* load and map other images that contain protocols the main binary will be using */
    /* NOTE: protocols must be configured via an ini file */
    if (ini_file != NULL)
    {
        OUTPUT_MSG("[+] Loading and mapping any configured protocols binaries");
        load_and_map_protocols(uc, &g_config.protos);
    }
    /*
     * NVRAM variables are stored on a buffer outside Unicorn VM memory
     * we then use this inside the variable related functions
     */
    OUTPUT_MSG("[+] Loading NVRAM");
    if (load_nvram(g_config.nvram_file) != 0)
    {
        ERROR_MSG("Failed to load NVRAM file.");
        return EXIT_FAILURE;
    }

    //OUTPUT_MSG("[+] Loading GUIDs");
    //if (load_guids(g_config.guids_file) != 0)
    //{
    //    WARNING_MSG("Failed to load GUIDs file.");
    //    /* Not fatal, so don't exit. */
    //}

    /*
     * create a fake EFI Boot and RunTime services table
     * that is basically code we intercept and return control into
     * our code so we can emulate the EFI services
     */
    OUTPUT_MSG("[+] Creating EFI service tables...");
    if (create_and_map_efi_system_table(uc) != 0)
    {
        ERROR_MSG("Failed to create EFI system table.");
        return EXIT_FAILURE;
    }

    struct bin_image* main_image = TAILQ_FIRST(&g_images);
    assert(main_image != NULL);

    OUTPUT_MSG("[+] Configuring Unicorn initial state...");
    /* set the initial registers state */
    uint64_t r_rip = main_image->base_addr + main_image->entrypoint;
    err = uc_reg_write(uc, UC_X86_REG_RIP, &r_rip);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RIP register");

    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE / 2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RSP register");

    /* RDX should always point to EFI SYSTEM TABLE address */
    uint64_t r_rdx = EFI_SYSTEM_TABLE_ADDRESS;
    err = uc_reg_write(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RDX register");
    /* RCX is the ImageHandle argument - let's keep it NULL for now */

    if (add_unicorn_hook(uc, UC_HOOK_INTR, hook_interrupt, 1, 0) != 0)
    {
        ERROR_MSG("Failed to add interrupts hook.");
        return EXIT_FAILURE;
    }
    /* add a hook to deal with unmapped memory exceptions */
    if (add_unicorn_hook(uc, UC_HOOK_MEM_UNMAPPED, hook_unmapped_mem, 1, 0) != 0)
    {
        ERROR_MSG("Failed to add unmapped memory hook.");
        return EXIT_FAILURE;
    }

    uint64_t total_images = 0;
    struct bin_image* tmp_image = NULL;
    TAILQ_FOREACH(tmp_image, &g_images, entries)
    {
        total_images++;
    }
    OUTPUT_MSG("[+] Total images loaded: %llu", total_images);

    /* start emulating the secondary images so they install whatever protocols they support */
    OUTPUT_MSG("[+] Starting secondary images emulation...");
    struct bin_image* secondary_image = NULL;
    TAILQ_FOREACH(secondary_image, &g_images, entries)
    {
        if (secondary_image->main == 0)
        {
            err = uc_emu_start(uc, secondary_image->tramp_start, secondary_image->tramp_end, 0, 0);
            VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to start Unicorn emulation for %s", secondary_image->file_path);
        }
    }

    /* reset Unicorn registers to a clean state before starting emulation of main image */
    initialize_unicorn_registers(uc);

    /* reset EFLAGS else we land in some weird bug where test rax,rax will not update EFLAGS for example */
    uint64_t r_eflags = 0x0;
    err = uc_reg_write(uc, UC_X86_REG_EFLAGS, &r_eflags);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to reset RFLAGS");

    /* RDX should always point to EFI SYSTEM TABLE address */
    err = uc_reg_write(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to reset EFI SYSTEM TABLE register");


    OUTPUT_MSG("[+] Starting main image emulation...");
    err = uc_emu_start(uc, main_image->tramp_start, main_image->tramp_end, 0, 0);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to start Unicorn emulation");

    OUTPUT_MSG("[+] All done, main image emulation complete.");

    uc_close(uc);
    return 0;
}
