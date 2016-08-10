#include "z80_debugwindow.h"
#include "Mem_z80.h"
#include "Mem_M68k.h"
#include "z80.h"
//#include "Star_68k.h"
#include "ram_dump.h"
#include "resource.h"

#include "ida_debmod.h"
#include <idp.hpp>
extern codemap_t g_codemap;
extern eventlist_t g_events;
extern bool handled_ida_event;

z80DebugWindow z80DW;

z80DebugWindow::z80DebugWindow()
{
}

z80DebugWindow::~z80DebugWindow()
{
}

extern "C" {
    extern uint32 hook_pc;
	void __fastcall z80TracePC(unsigned int pc);
	void __fastcall z80TraceRead(uint32 start,uint32 size);
	void __fastcall z80TraceWrite(uint32 start,uint32 size);
}

void __fastcall z80TracePC(unsigned int pc)
{
	z80DW.TracePC(pc);
}

void __fastcall z80TraceRead(uint32 start,uint32 size)
{
	z80DW.TraceRead(start,start+size-1);
}

void __fastcall z80TraceWrite(uint32 start,uint32 size)
{
	z80DW.TraceWrite(start,start+size-1);
}

void z80DebugWindow::TracePC(int pc)
{
    handled_ida_event = false;

    if (last_pc != 0 && hook_pc != 0 && hook_pc < MAX_ROM_SIZE)
        g_codemap[hook_pc] = std::pair<uint32, bool>(last_pc, true);

    prev_pc=last_pc;
	last_pc=pc;
	
	bool br=false;
	if (StepInto||StepOver==pc)
	{
		br=true;

        debug_event_t ev;
        ev.eid = STEP;
        ev.pid = 1;
        ev.tid = 1;
        ev.ea = last_pc;
        ev.handled = true;
        g_events.enqueue(ev, IN_BACK);

        handled_ida_event = true;

		if (StepInto)
			SetWhyBreak("StepInto");
		else
			SetWhyBreak("StepOver");
	}

	if (!br)
	{
		br=BreakPC(last_pc);
		if (br)
		{
			char bwhy[30];
			sprintf(bwhy,"Breakpoint PC:%06X",last_pc&0xFFFFFF);
			SetWhyBreak(bwhy);
		}
	}

	if (br)
	{
		StepInto=false;
		StepOver=-1;
		Breakpoint(last_pc);
	}
	//if ((OPC >> 12)==4&&!(OPC & 0x100)&&((OPC >> 6) & 0x3F)==58)
	//if((OPC >> 12)==6&&(OPC & 0xF00) == 0x100)
	//if ((OPC&0xFFC0)==0x4E80||//jsr
	//	(OPC&0xFF00)==0x6100)//bsr
	//	callstack.push_back(last_pc);

	//(OPC & 0x7)==5 && ((OPC >> 3) & 0x7)==6 && ((OPC >> 6) & 0x3F)==57 && !(OPC & 0x100) && (OPC >> 12)==4
	//if ((OPC&0xFFFF)==0x4E75)//rts
	//	callstack.pop_back();
}

void z80DebugWindow::TraceRead(uint32 start,uint32 stop)
{
	if (BreakRead(last_pc,start,stop))
	{
		char bwhy[33];
		sprintf(bwhy,"Read: %08X-%08X",start,stop);
		SetWhyBreak(bwhy);
		Breakpoint(last_pc);
	}
}

void z80DebugWindow::TraceWrite(uint32 start,uint32 stop)
{
	if (BreakWrite(last_pc,start,stop))
	{
		char bwhy[33];
		sprintf(bwhy,"Write: %08X-%08X",start,stop);
		SetWhyBreak(bwhy);
		Breakpoint(last_pc);
	}
}

void z80DebugWindow::DoStepOver()
{
	int pc=last_pc;

    if (is_call_insn(pc))
	  StepOver=pc;
	else
	{
		StepInto=true;
		StepOver=-1;
	}
}
