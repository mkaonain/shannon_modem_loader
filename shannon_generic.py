#!/bin/python3

# Samsung Shannon Modem Loader - Generic Functions for IDA Pro 7.4
# Adapted from Alexander Pick's original loader

import idc
import idaapi
import ida_segment
import ida_bytes
import ida_ua
import ida_name
import idautils
import ida_idp
import ida_nalt
import ida_search

import shannon_funcs

# set True for debug mode
is_debug = False

def DEBUG(msg):
    global is_debug
    if is_debug:
        idc.Message(msg)

# adds a memory segment to the database (7.4 compatible)
def add_memory_segment(seg_start, seg_size, seg_name, seg_type="DATA", sparse=True, seg_read=True, seg_write=True, seg_exec=True):
    if seg_size < 0:
        idc.Message("[e] cannot create a segment at %x with negative size %d\n" % (seg_start, seg_size))
        return

    if seg_start == 0xFFFFFFFF:
        idc.Message("[e] cannot create a segment at 0xFFFFFFFF\n")
        return

    seg_end = seg_start + seg_size

    # 7.4 compatible segment creation
    idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRelByte, idaapi.scPub)
    
    # Set segment class
    if seg_type == "CODE":
        idc.SetSegClass(seg_start, "CODE")
    else:
        idc.SetSegClass(seg_start, "DATA")

    # Set permissions
    perm = 0
    if seg_read:
        perm |= ida_segment.SEGPERM_READ
    if seg_write:
        perm |= ida_segment.SEGPERM_WRITE
    if seg_exec:
        perm |= ida_segment.SEGPERM_EXEC
    
    seg = idaapi.getseg(seg_start)
    if seg:
        seg.perm = perm

    # Set segment name
    idc.SegRename(seg_start, seg_name)

    # Make sparse if requested
    if sparse:
        for ea in range(seg_start, seg_end, 0x1000):
            ida_bytes.del_items(ea, 0, 0x1000)

# create a name at offset and validate if the name exists already (7.4 compatible)
def create_name(ea, name):
    for xref in idautils.XrefsTo(ea):
        func_start = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)

        if func_start != idaapi.BADADDR:
            if len(name) > 8:
                if "::" in name:
                    func_name = shannon_funcs.mangle_name(name)
                else:
                    func_name = shannon_funcs.function_find_name(name)

                ida_name.MakeName(func_start, func_name)
            else:
                idc.Message("[e] %x: function name too short: %s\n" % (func_start, name))

# helper function to set a name on the target of a LDR or B (7.4 compatible)
def get_ref_set_name(cur_ea, name):
    opcode = ida_ua.ua_mnem(cur_ea)

    if opcode == "LDR":
        target_ref = idc.GetOperandValue(cur_ea, 1)
        if target_ref != idaapi.BADADDR:
            target = ida_bytes.get_32bit(target_ref)
            ida_name.MakeName(target, name)

    if opcode == "B":
        target = idc.GetOperandValue(cur_ea, 0)
        if target != idaapi.BADADDR:
            ida_name.MakeName(target, name)

# resolves a string reference from offset (7.4 compatible)
def resolve_ref(str_addr):
    bytes = ida_bytes.get_bytes(str_addr, 4)
    if not bytes:
        idc.Message("[e] cannot resolve string reference at %x\n" % str_addr)
        return None

    str_offset = ida_bytes.get_32bit(str_addr)
    name = idc.GetString(str_offset)
    
    return name if name else None

# get first xref to string from a defined function (7.4 compatible)
def get_first_ref(ea):
    for xref in idautils.XrefsTo(ea):
        if idc.isCode(idc.GetFlags(xref.frm)):
            return xref.frm
    return idaapi.BADADDR

# creates strings which are at least 11 bytes long (7.4 compatible)
def create_long_strings(length=11):
    idc.Message("[i] creating long strings\n")

    current_ea = idaapi.cvar.inf.minEA
    end_ea = idaapi.cvar.inf.maxEA

    while current_ea < end_ea:
        current_ea = ida_search.find_binary(current_ea, end_ea, "00", 16, ida_search.SEARCH_DOWN)
        #current_ea = ida_search.FindBinary(current_ea, end_ea, "00", 16, ida_search.SEARCH_DOWN)
        if current_ea == idaapi.BADADDR:
            break

        str_len = ida_bytes.get_max_strlit_length(current_ea, ida_nalt.STRTYPE_C)
        if str_len >= length:
            ida_bytes.create_strlit(current_ea, str_len, ida_nalt.STRTYPE_C)
        
        current_ea += str_len if str_len > 0 else 1

# Get function metrics (7.4 compatible)
def get_metric(bl_target):
    loops = []
    branch = []
    ldr = []
    xrefs = []
    calls = []
    length = 0
    flow_size = 0

    func_start = idc.GetFunctionAttr(bl_target, idc.FUNCATTR_START)
    func_end = idc.GetFunctionAttr(bl_target, idc.FUNCATTR_END)

    func_cur = bl_target

    if func_end != idaapi.BADADDR and func_cur != idaapi.BADADDR:
        while func_cur < func_end:
            length += 1
            func_cur = idc.NextHead(func_cur)
            opcode = ida_ua.ua_mnem(func_cur)

            if not opcode:
                continue

            if ida_idp.is_ret_insn(func_cur):
                break

            if (ida_idp.is_basic_block_end(func_cur) or ida_idp.is_call_insn(func_cur)) and not ida_idp.is_ret_insn(func_cur):
                first_operand = idc.GetOperandValue(func_cur, 0)

                if first_operand != idaapi.BADADDR:
                    if ida_idp.is_call_insn(func_cur):
                        calls.append(func_cur)
                    elif first_operand >= func_start and func_cur > first_operand:
                        loops.append(func_cur)
                    else:
                        branch.append(func_cur)
                else:
                    idc.Message("[e] erroneous branch target at %x -> %x\n" % (func_cur, first_operand))

            if opcode and "LDR" in opcode:
                ldr.append(idc.GetOperandValue(func_cur, 1))

        # Get basic block count
        function = idaapi.get_func(func_start)
        if function:
            flow_chart = idaapi.FlowChart(function)
            flow_size = flow_chart.size
        else:
            idc.Message("[e] error getting flowchart for function at %x\n" % func_start)

        xrefs = list(idautils.XrefsTo(func_start))

    return [loops, branch, length, flow_size, xrefs, ldr, calls]

# print metrics from get_metrics() for debug reasons
def print_metrics(addr, metrics):
    idc.Message("[i] %x: loops: %d branch: %d length: %d basic blocks: %d xrefs: %d ldr: %d calls: %d\n" % (
        addr, len(metrics[0]), len(metrics[1]), metrics[2], metrics[3], len(metrics[4]), len(metrics[5]), len(metrics[6])))

# text search function for IDA 7.4
def search_text(start_ea, end_ea, text):
    current_ea = start_ea
    
    while current_ea < end_ea:
        current_str = idc.GetString(current_ea)
        if current_str:
            try:
                # Handle both str and bytes cases
                if isinstance(current_str, bytes):
                    if text.encode('utf-8') in current_str:
                        return current_ea
                else:
                    if text in current_str:
                        return current_ea
            except:
                pass
        current_ea = idc.NextHead(current_ea)
    
    return idaapi.BADADDR