# Stack Analysis IDA Python Module for ARM Processors
# Copyright (c) 2009 iZsh - izsh at iphone-dev.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from idaapi import *
from idc import *
from idautils import *

from izshcalltree import *
from izshbasicblock import *

####################################################
#
# ARM Stack Analysis
#
####################################################
# A few const and dicts...
ARM_REG_R0 = 0
ARM_REG_R1 = 1
ARM_REG_R2 = 2
ARM_REG_R3 = 3
ARM_REG_R4 = 4
ARM_REG_R5 = 5
ARM_REG_R6 = 6
ARM_REG_R7 = 7
ARM_REG_R8 = 8
ARM_REG_R9 = 9
ARM_REG_R10 = 10
ARM_REG_R11 = 11
ARM_REG_R12 = 12
ARM_REG_SP = 13
ARM_REG_LR = 14
ARM_REG_PC = 15

Reg2StrDict = dict([
  [ARM_REG_R0, "R0"],
  [ARM_REG_R1, "R1"],
  [ARM_REG_R2, "R2"],
  [ARM_REG_R3, "R3"],
  [ARM_REG_R4, "R4"],
  [ARM_REG_R5, "R5"],
  [ARM_REG_R6, "R6"],
  [ARM_REG_R7, "R7"],
  [ARM_REG_R8, "R8"],
  [ARM_REG_R9, "R9"],
  [ARM_REG_R10, "R10"],
  [ARM_REG_R11, "R11"],
  [ARM_REG_R12, "R12"],
  [ARM_REG_SP, "SP"],
  [ARM_REG_LR, "LR"],
  [ARM_REG_PC, "PC"]])

Str2RegDict = dict([
  ["R0", ARM_REG_R0],
  ["R1", ARM_REG_R1],
  ["R2", ARM_REG_R2],
  ["R3", ARM_REG_R3],
  ["R4", ARM_REG_R4],
  ["R5", ARM_REG_R5],
  ["R6", ARM_REG_R6],
  ["R7", ARM_REG_R7],
  ["R8", ARM_REG_R8],
  ["R9", ARM_REG_R9],
  ["R10", ARM_REG_R10],
  ["R11", ARM_REG_R11],
  ["R12", ARM_REG_R12],
  ["SP", ARM_REG_SP],
  ["LR", ARM_REG_LR],
  ["PC", ARM_REG_PC]])

# ===========================================================================
# Function: Bitfield2Reglist()
# ===========================================================================
# Description/Comment:
# Convert a register list represented as a bitfield to a normal list of
# register const
#
# Return: the list of the registers
# For example: Bitfield2Reglist(0xD) returns [ 1, 2, 3 ]
# ===========================================================================
def Bitfield2Reglist(Value):
  reg_list = []
  for reg in Reg2StrDict.keys():
    if Value & (1 << reg):
      reg_list.append(reg)
  return reg_list

# ===========================================================================
# Function: Reg2Str()
# ===========================================================================
# Description/Comment:
# Convert a register const value to its string representation
# ===========================================================================
def Reg2Str(Value):
  if Value in Reg2StrDict:
    return Reg2StrDict[Value]
  return None

# ===========================================================================
# Function: Reglist2Str()
# ===========================================================================
# Description/Comment:
# Convert a register list to its string representation
# ===========================================================================
def Reglist2Str(Reglist):
  return "{" + ", ".join(map(Reg2Str, Reglist)) + "}"

# In the following functions, the Stack argument is used to keep track
# of the stack. Each item in it has the following content:
# (SP offset, Description string, EA)
# wherein:
# - "SP Offset" is the displacement offset of the SP needed to store the value
# - "Description String" is a string to describe what the memory is used for
# - "EA" is the address of the instruction where the stack modification occured
#
# Also these functions are only called if SP is involved somehow (being the
# target register, or push/pop instructions)

# ===========================================================================
# Function: AnalyzePUSH()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the PUSH instruction and populate the Stack argument accordingly
#
# Since PUSH R8 (any > R7) doesn't exist in ARM we would need to keep track
# of the register contents to properly analyze the stack state.
# For instance, in the following example:
#
# PUSH    {R4-R7,LR}
# MOV     R6, R11
# MOV     R5, R10
# MOV     R4, R8
# PUSH    {R4-R6}
#
# the second push really just PUSHes {R8,R10,R11}, not really {R4-R6}.
# There are two ways we go could after this:
# - Either we could simulate the MOV throughout the normal analysis, but
#   that would give a false-sense of generecity, whereas we really just
#   do island parsing which is bound to eventually fail at some point.
# - Or, we could just try to backtrack to the nearest instructions modifying
#   the registers involved and apply a naive heuristic : only taking
#   into account MOV Rx, Ry with y > 7.
#
# In the case, the second approach is taken, assuming that, when failing,
# we'll probably have more important issues to solve anyway.
#
# ===========================================================================
def AnalyzePUSH(EA, Stack, MinEA, MaxEA, Debug = False):
  # Local functions to backtrack the real register as explained above
  # WARNING: this function will invalidate the current decoded instruction
  def BacktrackReg(Reg, MinEA):
    for head in reversed(Heads(MinEA, EA)):
      inslen = ua_ana0(head)
      if inslen == 0:
        continue
      insn = get_current_instruction()
      if not insn:
        continue
      op = get_instruction_operand(insn, 0)
      if not op:
        continue
      if op.type != o_reg or op.reg != Reg:
        continue
      # if we reach this point it means we identified a
      # MOV OurRegisterOfInterest, ...
      op = get_instruction_operand(insn, 1)
      # Then we apply our naive heuristic:
      # only accept MOV Regx, Regy with Regy > R7
      if not op or op.type != o_reg or op.reg <= 7:
        continue
      # Yeah we found something interesting ^^
      return op.reg
    return Reg
  def BacktrackReglist(Reglist, MinEA):
    return map(lambda reg: BacktrackReg(reg, MinEA), Reglist)

  inslen = ua_ana0(EA)
  if inslen == 0:
    return None
  insn = get_current_instruction()
  if not insn:
    return None
  op = get_instruction_operand(insn, 0)
  if not op:
    return None
  if op.type == o_reg:
    real_reg = BacktrackReg(op.reg, MinEA)
    # Warning: the current decoded instruction has been invalidated
    if Debug: print "  0x%x: PUSH %s" % (EA, Reg2StrDict[real_reg])
    Stack.append((-4, Reg2Str(real_reg), EA))
  elif op.type == o_idpspec1:
    reg_list = BacktrackReglist(Bitfield2Reglist(op.specval), MinEA)
    # Warning: the current decoded instruction has been invalidated
    if Debug: print "  0x%x: PUSH %s" % (EA, Reglist2Str(reg_list))
    for reg in reversed(reg_list):
      Stack.append((-4, Reg2Str(reg), EA))
  return None

# ===========================================================================
# Function: AnalyzePOP()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the POP instruction and depopulate the Stack argument accordingly
# ===========================================================================
def AnalyzePOP(EA, Stack, MinEA, MaxEA, Debug = False):
  inslen = idaapi.ua_ana0(EA)
  if inslen == 0:
    return None
  insn = get_current_instruction()
  if not insn:
    return None
  op = get_instruction_operand(insn, 0)
  if not op:
    return None
  if op.type == o_reg:
    if Debug: print "  0x%x: POP %s" % (EA, Reg2StrDict[op.reg])
    info = Stack.pop()
    # Sanity check, verify we are indeed poping a register
    assert(info[0] == -4)
  elif op.type == o_idpspec1:
    reg_list = Bitfield2Reglist(op.specval)
    if Debug: print "  0x%x: POP %s" % (EA, Reglist2Str(reg_list))
    for reg in reg_list:
      info = Stack.pop()
      # Sanity check, verify we are indeed poping a register
      assert(info[0] == -4)
  return None

# ===========================================================================
# Function: AnalyzeMOV()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the MOV instruction
# *Not Currently Implemented*
# ===========================================================================
def AnalyzeMOV(EA, Stack, MinEA, MaxEA, Debug = False):
  return None

# ===========================================================================
# Function: AnalyzeLDR()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the LDR instruction
#
# Currently only support
# LDR SP, =Value
# ===========================================================================
def AnalyzeLDR(EA, Stack, MinEA, MaxEA, Debug = False):
  inslen = idaapi.ua_ana0(EA)
  if inslen == 0:
    return None
  insn = get_current_instruction()
  if not insn:
    return None
  op = get_instruction_operand(insn, 1)
  if not op:
    return None
  if op.type == o_reg:
    op = get_instruction_operand(insn, 2)
  if not op:
    return None
  if op.type == o_mem:
    value = get_32bit(op.addr)
    if Debug: print "  0x%x: LDR SP, =0x%x" % (EA, value)
    return value
  return None

# ===========================================================================
# Function: AnalyzeADD()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the ADD instruction
#
# Only support:
# ADD SP, SP, immediate
# ADD SP, immediate
# ===========================================================================
def AnalyzeADD(EA, Stack, MinEA, MaxEA, Debug = False):
  inslen = idaapi.ua_ana0(EA)
  if inslen == 0:
    return None
  insn = get_current_instruction()
  if not insn:
    return None
  op = get_instruction_operand(insn, 1)
  if not op:
    return None
  if op.type == o_reg:
    op = get_instruction_operand(insn, 2)
  if not op:
    return None
  if op.type == o_imm:
    if Debug: print "  0x%x: ADD SP, SP, #0x%x" % (EA, op.value)
    info = Stack.pop()
    # Sanity check, verify we are indeed poping the same size
    assert(info[0] == -op.value)
  return None

# ===========================================================================
# Function: AnalyzeSUB()
# ===========================================================================
# EA: The address of the instruction
# Stack: the simulated stack
# MinEA: Minimum EA we can backtrack to
# MaxEA: Maximum EA we can forwardtrack to
# Debug: Enable the debug mode
#
# Description/Comment:
# Analyze the SUB instruction
#
# Only support:
# SUB SP, SP, immediate
# SUB SP, immediate
# ===========================================================================
def AnalyzeSUB(EA, Stack, MinEA, MaxEA, Debug = False):
  inslen = idaapi.ua_ana0(EA)
  if inslen == 0:
    return None
  insn = get_current_instruction()
  if not insn:
    return None
  op = get_instruction_operand(insn, 1)
  if not op:
    return None
  if op.type == o_reg:
    op = get_instruction_operand(insn, 2)
  if not op:
    return None
  if op.type == o_imm:
    if Debug: print "  0x%x: SUB SP, SP, #0x%x" % (EA, op.value)
    Stack.append((-op.value, "<0x%x byte of local vars>" % op.value, EA))
  return None

# ===========================================================================
# Function: AnalyzeBBStack()
# ===========================================================================
# BBNode: the basic block to analyze
# EndEA: the last instruction EA we'd like to analyze up to
#        by default it analyzes the whole block
# Debug: debug mode 
#
# Description/Comment:
# Analyze the stack of a basic block
# Return guessed SP base address and the stack
# ===========================================================================
def AnalyzeBBStack(BBNode, EndEA = MaxEA(), Debug = False):
  # Stack specific mnem
  stackops = dict([
    ["PUSH", AnalyzePUSH],
    ["POP", AnalyzePOP]])
  # General usage mnem
  genops = dict([
    ["MOV", AnalyzeMOV],
    ["MOVS", AnalyzeMOV],
    ["LDR", AnalyzeLDR],
    ["ADD", AnalyzeADD],
    ["ADDS", AnalyzeADD],
    ["SUB", AnalyzeSUB],
    ["SUBS", AnalyzeSUB]])
  # The stack holder
  stack = []
  sp_base = None
  # let's go through the instructions
  if EndEA > BBNode.EndEA:
    EndEA = BBNode.EndEA
  for head in Heads(BBNode.StartEA, NextHead(EndEA, MaxEA())):
    if isCode(GetFlags(head)):
      # We'll try to identify instructions which can modify the stack
      # We could just look at the spd value, but we would miss LDR
      # or MOV instruction (for instance).
      # Since we'll need to decode the operands anyway, it's probably better
      # not to use the spd value at all
      mnem = GetMnem(head)
      op0_type = GetOpType(head, 0)
      op0_value = GetOperandValue(head, 0)
      if Debug:
        print "0x%x: mnem = %s type = %d and value = %d" % (head, mnem, op0_type, op0_value)
      if mnem in stackops:
        sp_base = stackops[mnem](head, stack, BBNode.StartEA, EndEA, Debug)
      if op0_type == o_reg and op0_value == ARM_REG_SP and mnem in genops:
        sp_base = genops[mnem](head, stack, BBNode.StartEA, EndEA, Debug)
  # And finally return the stack
  return sp_base, stack

# ===========================================================================
# Function: AnalyzeFunctionStack()
# ===========================================================================
# EA: the address of the function
# NextCallEA: the address where the next call is being made
# Debug: debug mode 
#
# Description/Comment:
# Analyze the stack of a function
# We could put some heuristic like stopping as soon as the stack offset
# matches the one when calling the next subfunction... Especially since most
# of the time reading just the first BB is enough. But, what the hell...
#
# The function also returns the guessed SP base address
# This is a very limited feature insofar as it only analyzes LDR instructions
# while even hoping the code doesn't interlace LDR SP,(...) and push/pop
# but load it once for all at the beginning.
#
# Return the the guessed SP base address and the stack
# ===========================================================================
def AnalyzeFunctionStack(EA, NextCallEA, Debug = False):
  bb = BuildBasicBlockGraph(EA)
  bb_last = bb.FindNode(NextCallEA)
  path = bb_last.FindPathToRoot()
  stack = []
  sp_base = None
  for block in path:
    if block == bb_last:
      sp_addr, new_stack = AnalyzeBBStack(block, NextCallEA, Debug = Debug)
    else:
      sp_addr, new_stack = AnalyzeBBStack(block, Debug = Debug)
    if sp_addr:
      sp_base = sp_addr
    stack.extend(new_stack)
  return sp_base, stack

# ===========================================================================
# Function: AnalyzeFunctionsStack()
# ===========================================================================
# Functions: list of the functions
# SPBase = The SP base address
# Debug: debug mode 
#
# Description/Comment:
# Analyze the stack all the functions in a given path
# If SPBase is provided it will be used, otherwise the code will try to
# retrieve it from the analysis.
# ===========================================================================
def AnalyzeFunctionsStack(Functions, SPBase = None, Debug = False):
  sp_addr = SPBase
  for f in Functions:
    assert(f[3] == get_spd(get_func(f[0]), f[2]))
    sp_base, stack = AnalyzeFunctionStack(f[0], f[2], Debug = Debug)
    if sp_base and not SPBase:
      sp_addr = sp_base
    if not sp_addr:
      print "WARNING: the SP base pointer could not be inferred for the path."
      print "         The SP addresses will therefore be invalid."
      print "-" * 80
      sp_addr = 0x0
    print "fun %s calling next @0x%x with stack offset %xh : SP = 0x%x" % (f[1], f[2], f[3], sp_addr)
    local_addr = sp_addr
    for s in stack:
      local_addr += s[0]
      print "  " + hex(local_addr) + " - " + s[1]
    sp_addr += f[3]

# ===========================================================================
# Function: AnalyzeCallTreeStack()
# ===========================================================================
# EA: the address of the function
# Debug: debug mode 
#
# Description/Comment:
# Build a call tree and analyze the stack for it
# ===========================================================================
def AnalyzeCallTreeStack(EA, AskSPAddr = False, Debug = False):
  addr_asked = None
  if AskSPAddr:
    addr_asked = AskAddr(0xFFFFFF, ("Please enter the SP Base address if you want to.\n"
      "If no value is given, the script will try to retrieve it automagically.\n\n"))
  sp_base = None
  if addr_asked != 0xFFFFFF:
    sp_base = addr_asked
  print "Building Call Tree"
  min_spd_ea = get_min_spd_ea(get_func(EA))
  if min_spd_ea == BADADDR:
    min_spd_ea = get_func(EA).startEA
  t = BuildCallTree(EA, NextCallEA = min_spd_ea, Debug = Debug)
  print("Done.\n")
  t.Dump()  
  allpaths = t.FindAllPaths()
  for p in allpaths:
      print "\n" * 2
      print "=" * 80
      print "New Path"
      print "=" * 80
      AnalyzeFunctionsStack(p, SPBase = sp_base, Debug = Debug)
