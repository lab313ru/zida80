#include <stdio.h>
#include <memory.h>
#include <vector>


#include "z80_debugwindow.h"
#include "Mem_z80.h"
#include "Mem_M68k.h"
#include "z80.h"

#include "tracer.h"

extern bool hook_trace;

extern "C" {
    extern uint32 hook_address;
    extern uint32 hook_value;
    extern uint32 hook_pc;

    void trace_read_byte();
    void trace_read_word();
    void trace_read_dword();
    void trace_write_byte();
    void trace_write_word();
    void trace_write_dword();

    void trace_exec_pc();
};

void trace_exec_pc()
{
    z80DW.TracePC(hook_pc);
}

void trace_read_byte()
{
    z80DW.TraceRead(hook_address, hook_address);
}

void trace_read_word()
{
    z80DW.TraceRead(hook_address, hook_address + 1);
}

void trace_read_dword()
{
    z80DW.TraceRead(hook_address, hook_address + 3);
}

void trace_write_byte()
{
    z80DW.TraceWrite(hook_address, hook_address);
}

void trace_write_word()
{
    z80DW.TraceWrite(hook_address, hook_address + 1);
}

void trace_write_dword()
{
    z80DW.TraceWrite(hook_address, hook_address + 3);
}
