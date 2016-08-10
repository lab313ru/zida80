// Copyright (C) 2015 Dr. MefistO
//
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
//
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#include <Windows.h>

#include <ida.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <idp.hpp>

#include "ida_plugin.h"

#include "z80_debugwindow.h"
#include "resource.h"

#include "ida_debmod.h"
#include "ida_registers.h"

extern debugger_t debugger;

static bool plugin_inited;
static bool dbg_started;
static bool my_dbg;

static int idaapi hook_dbg(void *user_data, int notification_code, va_list va)
{
    switch (notification_code)
    {
    case dbg_notification_t::dbg_process_start:
        dbg_started = true;
        break;

    case dbg_notification_t::dbg_process_exit:
        dbg_started = false;
        break;
    }
    return 0;
}

static int idaapi idp_to_dbg_reg(int idp_reg)
{
    int reg_idx = idp_reg;
    
    /*
    if (idp_reg >= 0 && idp_reg <= 7)
        reg_idx = R_D0 + idp_reg;
    else if (idp_reg >= 8 && idp_reg <= 39)
        reg_idx = R_A0 + (idp_reg % 8);
    else if (idp_reg == 91)
        reg_idx = R_PC;
    else if (idp_reg == 92 || idp_reg == 93)
        reg_idx = R_SR;
    else if (idp_reg == 94)
        reg_idx = R_A7;
    else
    {
        char buf[MAXSTR];
        qsnprintf(buf, MAXSTR, "reg: %d\n", idp_reg);
        warning("SEND THIS MESSAGE TO meffi@lab313.ru:\n%s\n", buf);
        return 0;
    }
    */

    return reg_idx;
}

#ifdef _DEBUG
static const char* const optype_names[] =
{
    "o_void",
    "o_reg",
    "o_mem",
    "o_phrase",
    "o_displ",
    "o_imm",
    "o_far",
    "o_near",
    "o_idpspec0",
    "o_idpspec1",
    "o_idpspec2",
    "o_idpspec3",
    "o_idpspec4",
    "o_idpspec5",
};

static const char* const dtyp_names[] =
{
    "dt_byte",
    "dt_word",
    "dt_dword",
    "dt_float",
    "dt_double",
    "dt_tbyte",
    "dt_packreal",
    "dt_qword",
    "dt_byte16",
    "dt_code",
    "dt_void",
    "dt_fword",
    "dt_bitfild",
    "dt_string",
    "dt_unicode",
    "dt_3byte",
    "dt_ldbl",
    "dt_byte32",
    "dt_byte64",
};
#endif

typedef const regval_t &(idaapi *getreg_func_t)(const char *name, const regval_t *regvalues);

static int idaapi hook_idp(void *user_data, int notification_code, va_list va)
{
    switch (notification_code)
    {
    case processor_t::idp_notify::get_operand_info:
    {
        ea_t ea = va_arg(va, ea_t);
        int n = va_arg(va, int);
        int thread_id = va_arg(va, int);
        getreg_func_t getreg = va_arg(va, getreg_func_t);
        const regval_t *regvalues = va_arg(va, const regval_t *);
        idd_opinfo_t * opinf = va_arg(va, idd_opinfo_t *);

        opinf->ea = BADADDR;
        opinf->debregidx = 0;
        opinf->modified = false;
        opinf->value.ival = 0;
        opinf->value_size = 4;

        if (decode_insn(ea))
        {
            insn_t _cmd = cmd;
            op_t op = _cmd.Operands[n];

#ifdef _DEBUG
            if (my_dbg)
            {
                msg("cs=%x, ", _cmd.cs);
                msg("ip=%x, ", _cmd.ip);
                msg("ea=%x, ", _cmd.ea);
                msg("itype=%x, ", _cmd.itype);
                msg("size=%x, ", _cmd.size);
                msg("auxpref=%x, ", _cmd.auxpref);
                msg("segpref=%x, ", _cmd.segpref);
                msg("insnpref=%x, ", _cmd.insnpref);
                msg("insnpref=%x, ", _cmd.insnpref);

                msg("flags[");
                if (_cmd.flags & INSN_MACRO)
                    msg("INSN_MACRO|");
                if (_cmd.flags & INSN_MODMAC)
                    msg("OF_OUTER_DISP");
                msg("]\n");

                msg("type[%s], ", optype_names[op.type]);

                msg("flags[");
                if (op.flags & OF_NO_BASE_DISP)
                    msg("OF_NO_BASE_DISP|");
                if (op.flags & OF_OUTER_DISP)
                    msg("OF_OUTER_DISP|");
                if (op.flags & PACK_FORM_DEF)
                    msg("PACK_FORM_DEF|");
                if (op.flags & OF_NUMBER)
                    msg("OF_NUMBER|");
                if (op.flags & OF_SHOW)
                    msg("OF_SHOW");
                msg("], ");

                msg("dtyp[%s], ", dtyp_names[op.dtyp]);

                if (op.type == o_reg)
                    msg("reg=%x, ", op.reg);
                else if (op.type == o_displ || op.type == o_phrase)
                    msg("phrase=%x, ", op.phrase);
                else
                    msg("reg_phrase=%x, ", op.phrase);

                msg("addr=%x, ", op.addr);

                msg("value=%x, ", op.value);

                msg("specval=%x, ", op.specval);

                msg("specflag1=%x, ", op.specflag1);
                msg("specflag2=%x, ", op.specflag2);
                msg("specflag3=%x, ", op.specflag3);
                msg("specflag4=%x\n", op.specflag4);
            }
#endif

            int size = 0;
            switch (op.dtyp)
            {
            case dt_byte:
                size = 1;
                break;
            case dt_word:
                size = 2;
                break;
            default:
                size = 4;
                break;
            }

            opinf->value_size = size;

            switch (op.type)
            {
            case o_mem:
            case o_near:
            {
                opinf->ea = op.addr;
            } break;
            case o_imm:
            {
                opinf->ea = op.value;
            } break;
            case o_phrase:
            case o_reg:
            {
                int reg_idx = idp_to_dbg_reg(op.reg);
                regval_t reg = getreg(dbg->registers(reg_idx).name, regvalues);

                if (op.phrase >= 0x10 && op.phrase <= 0x1F || // (A0)..(A7), (A0)+..(A7)+
                    op.phrase >= 0x20 && op.phrase <= 0x27) // -(A0)..-(A7)
                {
                    if (op.phrase >= 0x20 && op.phrase <= 0x27)
                        reg.ival -= size;

                    opinf->ea = reg.ival;

                    switch (size)
                    {
                    case 1:
                    {
                        uint8_t b = 0;
                        dbg->read_memory(reg.ival, &b, 1);
                        opinf->value.set_int(b);
                    } break;
                    case 2:
                    {
                        uint16_t w = 0;
                        dbg->read_memory(reg.ival, &w, 2);
                        w = swap16(w);
                        opinf->value.set_int(w);
                    } break;
                    default:
                    {
                        uint32_t l = 0;
                        dbg->read_memory(reg.ival, &l, 4);
                        l = swap32(l);
                        opinf->value.set_int(l);
                    } break;
                    }
                }
                else
                    opinf->value = reg;

                opinf->debregidx = reg_idx;
            } break;
            case o_displ:
            {
                regval_t main_reg, add_reg;
                int main_reg_idx = idp_to_dbg_reg(op.reg);
                int add_reg_idx = idp_to_dbg_reg(op.specflag1 & 0xF);

                main_reg.ival = 0;
                add_reg.ival = 0;
                if (op.specflag2 & 0x10)
                {
                    add_reg = getreg(dbg->registers(add_reg_idx).name, regvalues);
                    if (op.specflag1 & 0x10)
                        add_reg.ival &= 0xFFFF;
                }

                if (main_reg_idx != R_PC)
                    main_reg = getreg(dbg->registers(main_reg_idx).name, regvalues);

                ea_t addr = (ea_t)main_reg.ival + op.addr + (ea_t)add_reg.ival;
                opinf->ea = addr;

                switch (size)
                {
                case 1:
                {
                    uint8_t b = 0;
                    dbg->read_memory(addr, &b, 1);
                    opinf->value.set_int(b);
                } break;
                case 2:
                {
                    uint16_t w = 0;
                    dbg->read_memory(addr, &w, 2);
                    w = swap16(w);
                    opinf->value.set_int(w);
                } break;
                default:
                {
                    uint32_t l = 0;
                    dbg->read_memory(addr, &l, 4);
                    l = swap32(l);
                    opinf->value.set_int(l);
                } break;
                }

                // TODO: displacements with PC and other regs unk_123(pc, d0.l); unk_111(d0, d2.w)
            } break;
            }

            opinf->ea &= 0xFFFFFF;

            return -1;
        }
    } break;
    }
    return 0;
}

//--------------------------------------------------------------------------
static void print_version()
{
    static const char format[] = NAME " debugger plugin v%s;\nAuthor: Dr. MefistO [Lab 313] <meffi@lab313.ru>.";
    info(format, VERSION);
    msg(format, VERSION);
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static bool init_plugin(void)
{
    if (ph.id != PLFM_Z80)
        return false;

    return true;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
    if (init_plugin())
    {
        dbg = &debugger;
        plugin_inited = true;
        dbg_started = false;
        my_dbg = false;

        hook_to_notification_point(HT_DBG, hook_dbg, NULL);
        hook_to_notification_point(HT_IDP, hook_idp, NULL);

        print_version();
        return PLUGIN_KEEP;
    }
    return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
    if (plugin_inited)
    {
        //term_plugin();
        unhook_from_notification_point(HT_DBG, hook_dbg, NULL);
        unhook_from_notification_point(HT_IDP, hook_idp, NULL);
        plugin_inited = false;
        dbg_started = false;
    }
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static void idaapi run(int /*arg*/)
{
}

//--------------------------------------------------------------------------
char comment[] = NAME " debugger plugin by Dr. MefistO.";

char help[] =
NAME " debugger plugin by Dr. MefistO.\n"
"\n"
"This module lets you debug Z80 sound drivers in IDA.\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_HIDE | PLUGIN_DBG | PLUGIN_MOD, // plugin flags
    init, // initialize

    term, // terminate. this pointer may be NULL.

    run, // invoke plugin

    comment, // long comment about the plugin
             // it could appear in the status line
             // or as a hint

    help, // multiline help about the plugin

    NAME " debugger plugin", // the preferred short name of the plugin

    "" // the preferred hotkey to run the plugin
};