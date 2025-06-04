#!/bin/python3

# Samsung Shannon Modem Loader - Structs for IDA Pro 7.4
# Adapted from Alexander Pick's original loader

import idaapi
import ida_nalt
import idc
import ida_struct
import ida_typeinf

import shannon_generic

# get struct by id (7.4 compatible)
def get_struct(tid):
    return ida_struct.get_struc(tid)

# get member by name (7.4 compatible)
def get_member_by_name(tif, name):
    return ida_struct.get_member_by_name(tif, name)

# get offset of member by name (7.4 compatible)
def get_offset_by_name(tif, name):
    member = get_member_by_name(tif, name)
    if member:
        return member.soff
    idc.Message("[e] get_offset_by_name(tif, %s): cannot get offset\n" % name)
    return None

# get_max_offset (7.4 compatible)
def get_max_offset(tif):
    return ida_struct.get_max_offset(tif)

# add_struc_member (7.4 compatible)
def add_struc_member(tid, name, offset, flag, typeid, nbytes):
    idc.AddStrucMember(tid, name, offset, flag, typeid, nbytes)

# ARM scatter structure (7.4 compatible)
def add_scatter_struct():
    #tid = idc.AddStruc(-1, "scatter", 0)
    tid = idc.AddStrucEx(-1, "scatter", 0)  # Explicit version
    if tid != idaapi.BADADDR:
        add_struc_member(tid, "src", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, -1, 4)
        add_struc_member(tid, "dst", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, -1, 4)
        add_struc_member(tid, "size", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "op", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, -1, 4)

# debug trace structure (7.4 compatible)
def add_dbt_struct():
    struct_id = idc.GetStrucIdByName("dbg_trace")
    if struct_id == idaapi.BADADDR:
        tid = idc.AddStrucEx(-1, "dbg_trace", 0)  # Explicit version
    #tid = idc.AddStruc(-1, "dbg_trace", 0)
    if tid != idaapi.BADADDR:
        add_struc_member(tid, "head", -1, idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "group", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "channel", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "num_param", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "msg_ptr", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, ida_nalt.STRTYPE_C, 4)
        add_struc_member(tid, "line", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "file", -1, idaapi.FF_DWORD, -1, 4)

# MPU table structure (7.4 compatible)
def add_mpu_region_struct():
    #tid = idc.AddStruc(-1, "mpu_region", 0)
    tid = idc.AddStrucEx(-1, "mpu_region", 0)  # Explicit version
    if tid != idaapi.BADADDR:
        add_struc_member(tid, "num", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "addr", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, -1, 4)
        add_struc_member(tid, "size", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "tex", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "ap", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "xn", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "se", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "ce", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "be", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "en", -1, idaapi.FF_DATA | idaapi.FF_DWORD, -1, 4)

# Task Structure (7.4 compatible)
def add_task_struct():
    #tid = idc.AddStruc(-1, "task_struct", 0)
    tid = idc.AddStrucEx(-1, "task_struct", 0)  # Explicit version
    if tid != idaapi.BADADDR:
        add_struc_member(tid, "gap_0", -1, idaapi.FF_BYTE, -1, 8)
        add_struc_member(tid, "state", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "flag", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_1", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_2", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "task_num", -1, idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "stack", -1, idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "gap_3", -1, idaapi.FF_BYTE, -1, 0x10)
        add_struc_member(tid, "task_name", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, ida_nalt.STRTYPE_C, 4)
        add_struc_member(tid, "priority", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_4", -1, idaapi.FF_BYTE, -1, 3)
        add_struc_member(tid, "stack_size", -1, idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "task_entry", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, -1, 4)
        add_struc_member(tid, "task_init", -1, idaapi.FF_DWORD, -1, 4)
        add_struc_member(tid, "gap_5", -1, idaapi.FF_BYTE, -1, 4)
        add_struc_member(tid, "gap_6", -1, idaapi.FF_BYTE, -1, 0x24)
        add_struc_member(tid, "gap_7", -1, idaapi.FF_BYTE, -1, 0x28)
        add_struc_member(tid, "gap_8", -1, idaapi.FF_BYTE, -1, 0x78)
        add_struc_member(tid, "gap_9", -1, idaapi.FF_BYTE, -1, 4)
        add_struc_member(tid, "gap_10", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_11", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_12", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "gap_13", -1, idaapi.FF_BYTE, -1, 1)
        add_struc_member(tid, "padding", -1, idaapi.FF_BYTE, -1, 16)