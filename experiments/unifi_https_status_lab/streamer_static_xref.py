#!/usr/bin/env python3
"""Bounded offline xref check for one privately supplied firmware binary.

Input is read from stdin; no firmware or device data is written. This checks
specific disassembly claims, not runtime behavior or device identity. Requires
the laboratory-only Capstone package and the exact previously copied binary.
"""

import hashlib
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs, CsError
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

EXPECTED = "30e9bd2cf236a0f0cfe4c86e458d9fec14a3c41059565f3bdb5450bfbbf12013"
MAX_BYTES = 1024 * 1024
data = sys.stdin.buffer.read(MAX_BYTES + 1)
if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != EXPECTED:
    raise SystemExit("unexpected or oversized firmware")
if data[:5] != b"\x7fELF\x01" or data.find(b"GetVideoSettings\x00") != 0x25F98:
    raise SystemExit("unexpected ELF or string layout")

# The exact hash binds these segment and section offsets to the read-only copy.
image_base = 0x10000
text_offset, text_size = 0x5EB0, 0x1EB38
target = image_base + 0x25F98
disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
disassembler.detail = True
disassembler.skipdata = True
instructions = list(disassembler.disasm(data[text_offset:text_offset + text_size], image_base + text_offset))
references = []
for index, inst in enumerate(instructions):
    try:
        operands = inst.operands
    except CsError:
        continue
    if (inst.mnemonic not in ("ldr", "ldr.w") or len(operands) < 2
            or operands[0].type != ARM_OP_REG or operands[1].type != ARM_OP_MEM
            or operands[1].mem.base != ARM_REG_PC):
        continue
    literal = ((inst.address + 4) & ~3) + operands[1].mem.disp
    offset = literal - image_base
    if not 0 <= offset <= len(data) - 4:
        continue
    value = struct.unpack_from("<I", data, offset)[0]
    for later in instructions[index + 1:index + 9]:
        if later.mnemonic not in ("add", "add.w"):
            continue
        try:
            later_operands = later.operands
        except CsError:
            continue
        if (len(later_operands) == 2 and later_operands[0].type == ARM_OP_REG
                and later_operands[0].reg == operands[0].reg and later_operands[1].type == ARM_OP_REG
                and later_operands[1].reg == ARM_REG_PC
                and ((value + later.address + 4) & 0xFFFFFFFF == target
                     or (value + ((later.address + 4) & ~3)) & 0xFFFFFFFF == target)):
            references.append((inst.address, later.address))

expected_references = [(0x16C2C, 0x16C36), (0x30136, 0x3013A)]
if references != expected_references:
    raise SystemExit("expected xrefs not recovered")
by_address = {inst.address: inst for inst in instructions}
for address, target_address in [(0x16CAC, 0x156A0), (0x3013C, 0x23C1C), (0x30154, 0x26CC8)]:
    inst = by_address.get(address)
    if (inst is None or inst.mnemonic not in ("bl", "blx") or not inst.operands
            or inst.operands[0].type != ARM_OP_IMM or inst.operands[0].imm != target_address):
        raise SystemExit("expected registration or dispatch branch not recovered")
handler = [inst for inst in instructions if 0x26CC8 <= inst.address < 0x26DEE]
calls = set()
for inst in handler:
    if inst.mnemonic in ("bl", "blx"):
        try:
            if inst.operands and inst.operands[0].type == ARM_OP_IMM:
                calls.add(inst.operands[0].imm)
        except CsError:
            pass
if not {0x1571C, 0x15DF8}.issubset(calls):
    raise SystemExit("expected encoder and IPC call sites not recovered")
print("firmware_sha256=" + EXPECTED)
print("get_video_settings_xrefs=" + ",".join(hex(first) for first, _ in references))
print("handler_registration_and_dispatch_branches=true")
print("handler_call_get_current_settings_plt=true")
print("handler_call_send_response_plt=true")
print("qualification=static_only")
