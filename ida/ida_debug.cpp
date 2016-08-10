#include <Windows.h>
#include <algorithm>
#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <diskio.hpp>
#include <auto.hpp>
#include <funcs.hpp>

#include "g_main.h"
#include "g_ddraw.h"
#include "g_dsound.h"
#include "resource.h"

#include "z80_debugwindow.h"
#include "Mem_z80.h"
#include "Mem_M68k.h"
#include "z80.h"

#include "ida_debmod.h"

#include "ida_registers.h"
#include "ida_debug.h"
#include "ida_plugin.h"

#include <vector>

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow);

codemap_t g_codemap;
eventlist_t g_events;

extern int Gens_Running;
qthread_t gens_thread = NULL;

#define BREAKPOINTS_BASE 0x00D00000

#define CHECK_FOR_START(x) {if (!Gens_Running) return x;}

register_info_t registers[] =
{
    { "AF", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "BC", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "DE", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "HL", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "SP", REGISTER_SP, RC_GENERAL, dt_word, NULL, 0 },
    { "PC", 0, RC_GENERAL, dt_word, NULL, 0 },

    { "IX", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "IY", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "I", 0, RC_GENERAL, dt_byte, NULL, 0 },
    { "R", 0, RC_GENERAL, dt_word, NULL, 0 },

    { "AF2", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "BC2", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "DE2", 0, RC_GENERAL, dt_word, NULL, 0 },
    { "HL2", 0, RC_GENERAL, dt_word, NULL, 0 },

    { "IP", REGISTER_IP, RC_GENERAL, dt_word, NULL, 0 },
    { "M68K_BANK", REGISTER_READONLY, RC_GENERAL, dt_dword, NULL, 0 },
};

static const char *register_classes[] =
{
    "General Registers",
    NULL
};

static void prepare_codemap()
{
    g_codemap.resize(MAX_ROM_SIZE);
    for (size_t i = 0; i < MAX_ROM_SIZE; ++i)
    {
        g_codemap[i] = std::pair<uint32, bool>(BADADDR, false);
    }
}

static void apply_codemap()
{
    if (g_codemap.empty()) return;

    msg("Applying codemap...\n");
    for (size_t i = 0; i < MAX_ROM_SIZE; ++i)
    {
        if (g_codemap[i].second && g_codemap[i].first)
        {
            auto_make_code((ea_t)i);
            noUsed((ea_t)i);
        }
        showAddr((ea_t)i);
    }
    noUsed(0, MAX_ROM_SIZE);

    for (size_t i = 0; i < MAX_ROM_SIZE; ++i)
    {
        if (g_codemap[i].second && g_codemap[i].first && !get_func((ea_t)i))
        {
            if (add_func(i, BADADDR))
                add_cref(g_codemap[i].first, i, fl_CN);
            noUsed((ea_t)i);
        }
        showAddr((ea_t)i);
    }
    noUsed(0, MAX_ROM_SIZE);
    msg("Codemap applied.\n");
}

inline static void toggle_pause()
{
    HWND hwndGens = FindWindowEx(NULL, NULL, "Gens", NULL);

    if (hwndGens != NULL)
        SendMessage(hwndGens, WM_COMMAND, ID_EMULATION_PAUSED, 0);
}

static void pause_execution()
{
    z80DW.DebugStop = true;

    if (Paused) return;
    toggle_pause();
}

static void continue_execution()
{
    z80DW.DebugStop = false;

    if (!Paused) return;
    toggle_pause();
}

static void finish_execution()
{
    if (gens_thread != NULL)
    {
        qthread_join(gens_thread);
        qthread_free(gens_thread);
        qthread_kill(gens_thread);
        gens_thread = NULL;
    }
}

// Initialize debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi init_debugger(const char *hostname,
    int port_num,
    const char *password)
{
    prepare_codemap();
    return true;
}

// Terminate debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi term_debugger(void)
{
    finish_execution();
    apply_codemap();
    return true;
}

// Return information about the n-th "compatible" running process.
// If n is 0, the processes list is reinitialized.
// 1-ok, 0-failed, -1-network error
// This function is called from the main thread
static int idaapi process_get_info(int n, process_info_t *info)
{
    return 0;
}

HINSTANCE GetHInstance()
{
    MEMORY_BASIC_INFORMATION mbi;
    SetLastError(ERROR_SUCCESS);
    VirtualQuery(GetHInstance, &mbi, sizeof(mbi));

    return (HINSTANCE)mbi.AllocationBase;
}

char cmdline[2048];
static int idaapi gens_process(void *ud)
{
    SetCurrentDirectoryA(idadir("plugins"));

    int rc;

    rc = WinMain(GetHInstance(), (HINSTANCE)NULL, cmdline, SW_NORMAL);

    debug_event_t ev;
    ev.eid = PROCESS_EXIT;
    ev.pid = 1;
    ev.handled = true;
    ev.exit_code = rc;

    g_events.enqueue(ev, IN_BACK);

    return rc;
}

// Start an executable to debug
// 1 - ok, 0 - failed, -2 - file not found (ask for process options)
// 1|CRC32_MISMATCH - ok, but the input file crc does not match
// -1 - network error
// This function is called from debthread
static int idaapi start_process(const char *path,
    const char *args,
    const char *startdir,
    int dbg_proc_flags,
    const char *input_path,
    uint32 input_file_crc32)
{
    qsnprintf(cmdline, sizeof(cmdline), "-rom \"%s\"", path);

    uint32 start = 0;

    z80DW.Breakpoints.clear();
    /*Breakpoint b(bp_type::BP_PC, start & 0xFFFFFF, start & 0xFFFFFF, true, false);
    z80DW.Breakpoints.push_back(b);*/

    g_events.clear();

    gens_thread = qthread_create(gens_process, NULL);

    return 1;
}

// rebase database if the debugged program has been rebased by the system
// This function is called from the main thread
static void idaapi rebase_if_required_to(ea_t new_base)
{
}

// Prepare to pause the process
// This function will prepare to pause the process
// Normally the next get_debug_event() will pause the process
// If the process is sleeping then the pause will not occur
// until the process wakes up. The interface should take care of
// this situation.
// If this function is absent, then it won't be possible to pause the program
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi prepare_to_pause_process(void)
{
    CHECK_FOR_START(1);
    pause_execution();
    return 1;
}

// Stop the process.
// May be called while the process is running or suspended.
// Must terminate the process in any case.
// The kernel will repeatedly call get_debug_event() and until PROCESS_EXIT.
// In this mode, all other events will be automatically handled and process will be resumed.
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi gens_exit_process(void)
{
    CHECK_FOR_START(1);

    HWND hwndGens = FindWindowEx(NULL, NULL, "Gens", NULL);
    if (hwndGens != NULL)
    {
        SendMessage(hwndGens, WM_CLOSE, 0, 0);
    }

    return 1;
}

// Get a pending debug event and suspend the process
// This function will be called regularly by IDA.
// This function is called from debthread
static gdecode_t idaapi get_debug_event(debug_event_t *event, int timeout_ms)
{
    while (true)
    {
        // are there any pending events?
        if (g_events.retrieve(event))
        {
            switch (event->eid)
            {
            case PROCESS_SUSPEND:
                apply_codemap();
                break;
            }
            return g_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        }
        if (g_events.empty())
            break;
    }
    return GDE_NO_EVENT;
}

// Continue after handling the event
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi continue_after_event(const debug_event_t *event)
{
    switch (event->eid)
    {
    case STEP:
    case PROCESS_SUSPEND:
        continue_execution();
        break;
    case PROCESS_EXIT:
        continue_execution();
        finish_execution();
        apply_codemap();
        break;
    }

    return 1;
}

// The following function will be called by the kernel each time
// when it has stopped the debugger process for some reason,
// refreshed the database and the screen.
// The debugger module may add information to the database if it wants.
// The reason for introducing this function is that when an event line
// LOAD_DLL happens, the database does not reflect the memory state yet
// and therefore we can't add information about the dll into the database
// in the get_debug_event() function.
// Only when the kernel has adjusted the database we can do it.
// Example: for imported PE DLLs we will add the exported function
// names to the database.
// This function pointer may be absent, i.e. NULL.
// This function is called from the main thread
static void idaapi stopped_at_debug_event(bool dlls_added)
{
}

// The following functions manipulate threads.
// 1-ok, 0-failed, -1-network error
// These functions are called from debthread
static int idaapi thread_suspend(thid_t tid) // Suspend a running thread
{
    return 0;
}

static int idaapi thread_continue(thid_t tid) // Resume a suspended thread
{
    return 0;
}

static int idaapi set_step_mode(thid_t tid, resume_mode_t resmod) // Run one instruction in the thread
{
    switch (resmod)
    {
    case RESMOD_INTO:    ///< step into call (the most typical single stepping)
        z80DW.StepInto = 1;
        z80DW.DebugStop = false;
        break;
    case RESMOD_OVER:    ///< step over call
        z80DW.DoStepOver();
        z80DW.DebugStop = false;
        break;
    }

    return 1;
}

// Read thread registers
//	tid	- thread id
//	clsmask- bitmask of register classes to read
//	regval - pointer to vector of regvals for all registers
//			 regval is assumed to have debugger_t::registers_size elements
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
    if (clsmask & RC_GENERAL)
    {
        values[R_AF].ival = M_Z80.AF.w.AF;
        values[R_BC].ival = M_Z80.BC.w.BC;
        values[R_DE].ival = M_Z80.DE.w.DE;
        values[R_HL].ival = M_Z80.HL.w.HL;
        values[R_SP].ival = M_Z80.SP.w.SP;
        values[R_PC].ival = M_Z80.PC.w.PC;

        values[R_IX].ival = M_Z80.IX.w.IX;
        values[R_IY].ival = M_Z80.IY.w.IY;
        values[R_I].ival = M_Z80.I;
        values[R_R].ival = M_Z80.R.w.R;

        values[R_AF2].ival = M_Z80.AF2.w.AF2;
        values[R_BC2].ival = M_Z80.BC2.w.BC2;
        values[R_DE2].ival = M_Z80.DE2.w.DE2;
        values[R_HL2].ival = M_Z80.HL2.w.HL2;

        values[R_IP].ival = z80DW.last_pc;
        values[R_BANK].ival = Bank_Z80;
    }

    return 1;
}

// Write one thread register
//	tid	- thread id
//	regidx - register index
//	regval - new value of the register
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi write_register(thid_t tid, int regidx, const regval_t *value)
{
    switch (regidx)
    {
    case R_AF:
        M_Z80.AF.w.AF = value->ival;
        break;
    case R_BC:
        M_Z80.BC.w.BC = value->ival;
        break;
    case R_DE:
        M_Z80.DE.w.DE = value->ival;
        break;
    case R_HL:
        M_Z80.HL.w.HL = value->ival;
        break;
    case R_SP:
        M_Z80.SP.w.SP = value->ival;
        break;
    case R_PC:
        M_Z80.PC.w.PC = value->ival;
        break;
    case R_IX:
        M_Z80.IX.w.IX = value->ival;
        break;
    case R_IY:
        M_Z80.IY.w.IY = value->ival;
        break;
    case R_I:
        M_Z80.I = value->ival;
        break;
    case R_R:
        M_Z80.R.w.R = value->ival;
        break;
    case R_AF2:
        M_Z80.AF2.w.AF2 = value->ival;
        break;
    case R_BC2:
        M_Z80.BC2.w.BC2 = value->ival;
        break;
    case R_DE2:
        M_Z80.DE2.w.DE2 = value->ival;
        break;
    case R_HL2:
        M_Z80.HL2.w.HL2 = value->ival;
        break;
    case R_IP:
        z80DW.last_pc = value->ival;
        break;
    case R_BANK:
        Bank_Z80 = value->ival;
        break;
    }

    return 1;
}

//
// The following functions manipulate bytes in the memory.
//
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//	0: failed
//	1: new memory layout is returned
// This function is called from debthread
static int idaapi get_memory_info(meminfo_vec_t &areas)
{
    memory_info_t info;

    // Don't remove this loop
    for (int i = 0; i < get_segm_qty(); ++i)
    {
        char buf[MAX_PATH];

        segment_t *segm = getnseg(i);

        info.startEA = segm->startEA;
        info.endEA = segm->endEA;

        get_segm_name(segm, buf, sizeof(buf));
        info.name = buf;

        get_segm_class(segm, buf, sizeof(buf));
        info.sclass = buf;

        info.sbase = 0;
        info.perm = SEGPERM_READ | SEGPERM_WRITE;
        info.bitness = 1;
        areas.push_back(info);
    }
    // Don't remove this loop

    return 1;
}

// Read process memory
// Returns number of read bytes
// 0 means read error
// -1 means that the process does not exist anymore
// This function is called from debthread
static ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
    CHECK_FOR_START(0);
    for (size_t i = 0; i < size; ++i)
    {
        unsigned char value = (unsigned char)(Ram_Z80[ea + i]);
        ((UINT8*)buffer)[i] = value;
    }

    return size;
}
// Write process memory
// Returns number of written bytes, -1-fatal error
// This function is called from debthread
static ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
    return 0;
}

// Is it possible to set breakpoint?
// Returns: BPT_...
// This function is called from debthread or from the main thread if debthread
// is not running yet.
// It is called to verify hardware breakpoints.
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
    switch (type)
    {
        //case BPT_SOFT:
    case BPT_EXEC:
    case BPT_READ: // there is no such constant in sdk61
    case BPT_WRITE:
    case BPT_RDWR:
        return BPT_OK;
    }

    return BPT_BAD_TYPE;
}

// Add/del breakpoints.
// bpts array contains nadd bpts to add, followed by ndel bpts to del.
// returns number of successfully modified bpts, -1-network error
// This function is called from debthread
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
    CHECK_FOR_START(0);

    for (int i = 0; i < nadd; ++i)
    {
        ea_t start = bpts[i].ea;
        ea_t end = bpts[i].ea + bpts[i].size - 1;
        bp_type type1;
        int type2 = 0;

        switch (bpts[i].type)
        {
        case BPT_EXEC:
            type1 = bp_type::BP_PC;
            break;
        case BPT_READ:
            type1 = bp_type::BP_READ;
            break;
        case BPT_WRITE:
            type1 = bp_type::BP_WRITE;
            break;
        case BPT_RDWR:
            type1 = bp_type::BP_READ;
            type2 = (int)bp_type::BP_WRITE;
            break;
        }

        Breakpoint b(type1, start & 0xFFFFFF, end & 0xFFFFFF, true, false);
        z80DW.Breakpoints.push_back(b);

        if (type2 != 0)
        {
            Breakpoint b((bp_type)type2, start & 0xFFFFFF, end & 0xFFFFFF, true, false);
            z80DW.Breakpoints.push_back(b);
        }

        bpts[i].code = BPT_OK;
    }

    for (int i = 0; i < ndel; ++i)
    {
        ea_t start = bpts[nadd + i].ea;
        ea_t end = bpts[nadd + i].ea + bpts[nadd + i].size - 1;
        bp_type type1;
        int type2 = 0;

        switch (bpts[nadd + i].type)
        {
        case BPT_EXEC:
            type1 = bp_type::BP_PC;
            break;
        case BPT_READ:
            type1 = bp_type::BP_READ;
            break;
        case BPT_WRITE:
            type1 = bp_type::BP_WRITE;
            break;
        case BPT_RDWR:
            type1 = bp_type::BP_READ;
            type2 = (int)bp_type::BP_WRITE;
            break;
        }

        start &= 0xFFFFFF;
        end &= 0xFFFFFF;

        for (auto j = z80DW.Breakpoints.begin(); j != z80DW.Breakpoints.end(); )
        {
            if (j->type != type1 ||
                !(start <= j->end && end >= j->start))
            {
                ++j;
            }
            else
            {
                j = z80DW.Breakpoints.erase(j);
            }
        }

        if (type2 != 0)
        {
            for (auto j = z80DW.Breakpoints.begin(); j != z80DW.Breakpoints.end(); )
            {
                if (j->type != (bp_type)type2 ||
                    !(start <= j->end && end >= j->start))
                {
                    ++j;
                }
                else
                {
                    j = z80DW.Breakpoints.erase(j);
                }
            }
        }

        bpts[nadd + i].code = BPT_OK;
    }

    return (ndel + nadd);
}

// Update low-level (server side) breakpoint conditions
// Returns nlowcnds. -1-network error
// This function is called from debthread
static int idaapi update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
    for (int i = 0; i < nlowcnds; ++i)
    {
        ea_t start = lowcnds[i].ea;
        ea_t end = lowcnds[i].ea + lowcnds[i].size - 1;
        bp_type type1;
        int type2 = 0;

        switch (lowcnds[i].type)
        {
        case BPT_EXEC:
            type1 = bp_type::BP_PC;
            break;
        case BPT_READ:
            type1 = bp_type::BP_READ;
            break;
        case BPT_WRITE:
            type1 = bp_type::BP_WRITE;
            break;
        case BPT_RDWR:
            type1 = bp_type::BP_READ;
            type2 = (int)bp_type::BP_WRITE;
            break;
        }

        start &= 0xFFFFFF;
        end &= 0xFFFFFF;

        for (auto j = z80DW.Breakpoints.begin(); j != z80DW.Breakpoints.end(); ++j)
        {
            if (j->type != type1) continue;

            if (start <= j->end && end >= j->start)
            {
                j->is_forbid = (lowcnds[i].cndbody.empty() ? false : ((lowcnds[i].cndbody[0] == '1') ? true : false));
            }
        }

        if (type2 != 0)
        {
            for (auto j = z80DW.Breakpoints.begin(); j != z80DW.Breakpoints.end(); ++j)
            {
                if (j->type != (bp_type)type2) continue;

                if (start <= j->end && end >= j->start)
                {
                    j->is_forbid = (lowcnds[i].cndbody.empty() ? false : ((lowcnds[i].cndbody[0] == '1') ? true : false));
                }
            }
        }
    }

    return nlowcnds;
}

// Calculate the call stack trace
// This function is called when the process is suspended and should fill
// the 'trace' object with the information about the current call stack.
// Returns: true-ok, false-failed.
// If this function is missing or returns false, IDA will use the standard
// mechanism (based on the frame pointer chain) to calculate the stack trace
// This function is called from the main thread
static bool idaapi update_call_stack(thid_t tid, call_stack_t *trace)
{
    CHECK_FOR_START(0);

    trace->dirty = false;
    size_t n = z80DW.callstack.size();
    trace->resize(n);
    for (size_t i = 0; i < n; i++)
    {
        call_stack_info_t &ci = (*trace)[i];
        ci.callea = z80DW.callstack[i];
        ci.funcea = BADADDR;
        ci.fp = BADADDR;
        ci.funcok = true;
    }

    return true;
}

//--------------------------------------------------------------------------
//
//	  DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

debugger_t debugger =
{
    IDD_INTERFACE_VERSION,
    NAME, // Short debugger name
    125, // Debugger API module id
    "z80", // Required processor name
    DBG_FLAG_NOHOST | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_FAKE_ATTACH | DBG_FLAG_SAFE | DBG_FLAG_NOPASSWORD | DBG_FLAG_NOSTARTDIR | DBG_FLAG_LOWCNDS | DBG_FLAG_CONNSTRING | DBG_FLAG_ANYSIZE_HWBPT,

    register_classes, // Array of register class names
    RC_GENERAL, // Mask of default printed register classes
    registers, // Array of registers
    qnumber(registers), // Number of registers

    0x1000, // Size of a memory page

    NULL, // bpt_bytes, // Array of bytes for a breakpoint instruction
    NULL, // bpt_size, // Size of this array
    0, // for miniidbs: use this value for the file type after attaching

    DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER, // Resume modes

    init_debugger,
    term_debugger,

    process_get_info,

    start_process,
    NULL, // attach_process,
    NULL, // detach_process,
    rebase_if_required_to,
    prepare_to_pause_process,
    gens_exit_process,

    get_debug_event,
    continue_after_event,

    NULL, // set_exception_info
    stopped_at_debug_event,

    thread_suspend,
    thread_continue,
    set_step_mode,

    read_registers,
    write_register,

    NULL, // thread_get_sreg_base

    get_memory_info,
    read_memory,
    write_memory,

    is_ok_bpt,
    update_bpts,
    update_lowcnds,

    NULL, // open_file
    NULL, // close_file
    NULL, // read_file

    NULL, // map_address,

    NULL, // set_dbg_options
    NULL, // get_debmod_extensions
    update_call_stack,

    NULL, // appcall
    NULL, // cleanup_appcall

    NULL, // eval_lowcnd

    NULL, // write_file

    NULL, // send_ioctl
};