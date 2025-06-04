#!/bin/python3

# Samsung Shannon Modem Loader for IDA Pro 7.4
# Adapted from Alexander Pick's original loader

import idc
import idaapi
import idautils
import ida_idp
import ida_auto
import ida_bytes
import ida_nalt
import ida_name
import ida_expr
import ida_kernwin
import ida_segment
import ida_ida
import ida_typeinf

import struct

import shannon_structs
import shannon_generic

def make_dbt():
    sc = idautils.Strings()
    sc.setup(strtypes=[ida_nalt.STRTYPE_C],
             ignore_instructions=True, minlen=4)
    sc.refresh()

    for i in sc:
        if "DBT:" in str(i):
            struct_name = "dbg_trace"
            struct_id = idc.GetStrucIdByName(struct_name)
            if struct_id == idaapi.BADADDR:
                idc.Message("[e] Structure %s not found\n" % struct_name)
                continue
            struct_size = idc.GetStrucSize(struct_id)
            offset = i.ea + str(i).find("DBT:")
            
            # Use 7.4-compatible functions
            ida_bytes.del_items(offset, 0, struct_size)
            ida_bytes.create_struct(offset, struct_size, struct_id)

def accept_file(fd, fname):
    fd.seek(0x0)
    try:
        image_type = fd.read(0x3)
    except UnicodeDecodeError:
        return 0

    if image_type == b"TOC":
        return {"format": "Shannon Baseband Image", "processor": "arm"}
    return 0

def load_file(fd, neflags, format):
    version_string = None

    # Set processor type (7.4 compatible)
    idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    idc.SetProcessorType("arm", ida_idp.SETPROC_LOADER)
    
    # Process configuration lines
    idc.SetCharPrm(idc.INF_COMPILER, idc.COMP_GNU)
    idc.SetLongPrm(idc.INF_AF, idc.GetLongPrm(idc.INF_AF) & ~idc.AF_FINAL)  # Disable coagulate and collapse
    
    # Set compiler info (7.4 compatible)
    idc.SetCharPrm(idc.INF_COMPILER, idc.COMP_GNU)
    idaapi.cvar.inf.cc.id = idaapi.CM_CC_FASTCALL  # or CM_CC_ARM for standard ARM
    idaapi.cvar.inf.cc.cm = idaapi.CM_N32_F48      # if needed for ARM
    idaapi.cvar.inf.cc.abi = 0                     # default ABI

    #idaapi.ph_set_calling_convention(idaapi.CM_CC_FASTCALL)
    #idc.SetLongPrm(idc.INF_CC, idaapi.CM_CC_FASTCALL)
    
    # Data type sizes
    idc.SetCharPrm(idc.INF_DATATYPES, 
                  (1 << 0) |  # bool = 1 byte
                  (2 << 4) |  # short = 2 bytes
                  (4 << 8) |  # int = 4 bytes
                  (4 << 12) | # enum = 4 bytes
                  (4 << 16) | # long = 4 bytes
                  (8 << 20))  # llong = 8 bytes
    
    # Load type library
    idc.Til2Idb(-1, "armv12")
    
    if neflags & idaapi.NEF_RELOAD != 0:
        return 1

    # Clear output window (7.4 compatible)
    output = ida_kernwin.find_widget("Output window")
    if output:
        ida_kernwin.activate_widget(output, True)
        idaapi.process_ui_action("msglist:Clear")

    idc.Message("\nIDA Pro 7.4 Shannon Modem Loader\n")
    idc.Message("More: https://github.com/alexander-pick/shannon_modem_loader\n\n")

    start_offset = 0x20
    tensor = False

    while True:
        fd.seek(start_offset)
        entry = fd.read(0x20)

        try:
            toc_info = struct.unpack("12sIIIII", entry)
        except:
            break

        seg_name = str(toc_info[0], "UTF-8").strip("\x00")
        if seg_name == "":
            break

        seg_start = toc_info[2]
        seg_end = toc_info[2] + toc_info[3]

        if seg_name == "OFFSET" and seg_start == 0x0:
            idc.Message("[i] found OFFSET, skipping\n")
            start_offset += 0x20
            continue

        if seg_name == "GVERSION" and seg_start == 0x0:
            idc.Message("[i] found GVERSION, this is Tensor land\n")
            tensor = True
            start_offset += 0x20
            continue

        # Create segment (7.4 compatible)
        idc.Message("[i] adding %s\n" % seg_name)
        idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub)
        
        if "NV" in seg_name:
            idc.SetSegClass(seg_start, "DATA")
        else:
            idc.SetSegClass(seg_start, "CODE")

        idc.SegRename(seg_start, seg_name + "_file")
        fd.file2base(toc_info[1], seg_start, seg_end, 0)

        # Set segment permissions
        if seg_name in ["BOOT", "MAIN", "VSS"]:
            seg = idaapi.getseg(seg_start)
            if seg:
                seg.perm = ida_segment.SEGPERM_EXEC | ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE

        if seg_name == "BOOT":
            idaapi.add_entry(seg_start, seg_start, "bootloader_entry", 1)
            idc.MakeComm(seg_start, "bootloader entry point")
            ida_auto.auto_make_code(seg_start)
            #ida_auto.AutoMark(seg_start, ida_auto.AU_CODE)

        if seg_name == "MAIN":
            version_addr = shannon_generic.search_text(seg_start, seg_end, "_ShannonOS_")
            if version_addr:
                version_string = idc.GetString(version_addr)

            ida_auto.auto_make_code(seg_start)
            #ida_auto.AutoMark(seg_start, ida_auto.AU_CODE)
            idc.MakeComm(seg_start, "vector table")

            # Add vector table entries
            for offset, name in [(0, "reset"),
                                (4, "undef_inst"),
                                (8, "soft_int"),
                                (12, "prefetch_abort"),
                                (16, "data_abort"),
                                (20, "reserved_1"),
                                (24, "irq"),
                                (28, "fiq")]:
                ea = seg_start + offset
                idaapi.add_entry(ea, ea, name, 1)

        start_offset += 0x20

    # Post-processing
    shannon_generic.create_long_strings()
    shannon_structs.add_dbt_struct()
    make_dbt()
    shannon_structs.add_scatter_struct()
    shannon_structs.add_mpu_region_struct()
    shannon_structs.add_task_struct()

    # Run post-processing script
    try:
        postproc_path = os.path.join(idaapi.idadir("python"), "shannon_postprocess.py")
        if os.path.exists(postproc_path):
            exec(open(postproc_path).read())
    except:
        pass

    if version_string:
        idc.Message("[i] RTOS version:%s\n" % version_string.decode().replace("_", " "))

    idc.Message("[i] loader done, starting auto analysis\n")
    return 1