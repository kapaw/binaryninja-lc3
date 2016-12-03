#!/usr/bin/env python
from binaryninja import *
from struct import unpack

# Operand types
TYPE_DR = 0
TYPE_SR = 1
TYPE_BR = 2
TYPE_IMM = 3
TYPE_PC_OFFSET = 4
TYPE_REG_OFFSET = 5
TYPE_TRAPVECT = 6

# Helpers
def TwosComplement(number, bits):
    mask = 2**(bits - 1)
    return -(number & mask) + (number & ~mask)

def GetSignedValue(data, offset, bits):
    return TwosComplement(GetValue(data, offset, bits), bits)

def GetValue(data, offset, bits):
    return ((data >> offset) & (2**bits-1))

def GetRegister(data, offset):
    return GetValue(data, offset, 3)

def GetInstructionName(opcode, data):
    instruction = {
    0b0001: 'ADD',
    0b0101: 'AND',
    0b0000: 'BR',   # Brn, BRz, BRp, BRzp, BRnp, BRnz, BRnzp are variations
    0b1100: 'JMP',  # RET is a variation
    0b0100: 'JSR',  # JSRR is a variation
    0b0010: 'LD',
    0b1010: 'LDI',
    0b0110: 'LDR',
    0b1110: 'LEA',
    0b1001: 'NOT',
    0b1000: 'RTI',
    0b0011: 'ST',
    0b1011: 'STI',
    0b0111: 'STR',
    0b1111: 'TRAP',
    0b1101: None    # "reserved"
    }[opcode]

    # Handle the variations
    if instruction == 'BR':
        n = GetValue(data, 11, 1) == 1
        z = GetValue(data, 10, 1) == 1
        p = GetValue(data, 9, 1) == 1
        if n and z and p:
            instruction += 'nzp'
        elif n and z:
            instruction += 'nz'
        elif n and p:
            instruction += 'np'
        elif z and p:
            instruction += 'zp'
        elif p:
            instruction += 'p'
        elif z:
            instruction += 'z'
        elif n:
            instruction += 'n'
    elif instruction == 'JMP':
        if GetRegister(data, 6) == 7:
            instruction = 'RET'
    elif instruction == 'JSR':
        if GetValue(data, 11, 1) == 0:
            instruction = 'JSRR'

    return instruction

def GetOperandTypes(instruction, data):
    # Operand types for ADD and AND varies depending on bit 5
    if instruction in ['ADD', 'AND']:
        if GetValue(data, 5, 1):
            instruction += "_imm"

    # Operand type is the same for all BR[nzp] instructions
    if instruction.startswith('BR'):
        instruction = 'BR'
    
    return {
        'ADD':      [TYPE_DR, TYPE_SR, TYPE_SR],
        'ADD_imm':  [TYPE_DR, TYPE_SR, TYPE_IMM],
        'AND':      [TYPE_DR, TYPE_SR, TYPE_SR],
        'AND_imm':  [TYPE_DR, TYPE_SR, TYPE_IMM],
        'BR':       [TYPE_PC_OFFSET],
        'JMP':      [TYPE_BR],
        'JSR':      [TYPE_PC_OFFSET],
        'JSRR':     [TYPE_BR],
        'LD':       [TYPE_DR, TYPE_PC_OFFSET],
        'LDI':      [TYPE_DR, TYPE_PC_OFFSET],
        'LDR':      [TYPE_DR, TYPE_BR, TYPE_REG_OFFSET],
        'LEA':      [TYPE_DR, TYPE_PC_OFFSET],
        'NOT':      [TYPE_DR, TYPE_SR],
        'RET':      None,
        'RTI':      None,
        'ST':       [TYPE_SR, TYPE_PC_OFFSET],
        'STI':      [TYPE_SR, TYPE_PC_OFFSET],
        'STR':      [TYPE_SR, TYPE_BR, TYPE_REG_OFFSET],
        'TRAP':     [TYPE_TRAPVECT]
    }[instruction]

def GetOperands(instruction, data):
    # Extract operands from instruction
    operands = []
    if instruction in ['ADD', 'AND']:
        operands.append(GetRegister(data, 9))
        operands.append(GetRegister(data, 6))
        if GetValue(data, 5, 1) == 1:
            operands.append(GetSignedValue(data, 0, 5))
        else:
            operands.append(GetRegister(data, 0))
    elif instruction.rstrip('nzp') in ['BR']:
        operands.append(GetSignedValue(data, 0, 9))
    elif instruction in ['JMP']:
        operands.append(GetRegister(data, 6))
    elif instruction in ['JSR']:
        operands.append(GetValue(data, 0, 11))
    elif instruction in ['JSRR']:
        operands.append(GetRegister(data, 6))
    elif instruction in ['LD', 'LDI', 'LEA', 'ST', 'STI']:
        operands.append(GetRegister(data, 9))
        operands.append(GetSignedValue(data, 0, 9))
    elif instruction in ['LDR', 'STR']:
        operands.append(GetRegister(data, 9))
        operands.append(GetRegister(data, 6))
        operands.append(GetValue(data, 0, 6))
    elif instruction in ['NOT']:
        operands.append(GetRegister(data, 9))
        operands.append(GetRegister(data, 6))
    elif instruction in ['TRAP']:
        operands.append(GetValue(data, 0, 8))

    return operands

# LC3 Architecture class
class LC3(Architecture):
    name = 'LC3'
    address_size = 2
    default_int_size = 1
    max_instr_length = 2
    opcode_display_length = 8
    
    regs = {
        'R0': RegisterInfo('R0', 1),        
        'R1': RegisterInfo('R1', 1),        
        'R2': RegisterInfo('R2', 1),        
        'R3': RegisterInfo('R3', 1),        
        'R4': RegisterInfo('R4', 1),        
        'R5': RegisterInfo('R5', 1),        
        'R6': RegisterInfo('R6', 1),        
        'R7': RegisterInfo('R7', 1),        
    }
    flags = ['n', 'z', 'p']
    flag_roles = {
        'n': NegativeSignFlagRole,
        'z': ZeroFlagRole,
        'p': PositiveSignFlagRole,
    }
    stack_pointer = 'R7'
    
    def decode_instruction(self, data, addr):
        if len(data) < 2:
            return None, None, None

        instruction_bytes = unpack('>H', data[0:2])[0]
        opcode = (instruction_bytes >> 12)
        instruction = GetInstructionName(opcode, instruction_bytes)

        if not instruction:
            print 'Bad opcode: %x @ %#x' % (opcode, addr)
            return None, None, None

        operand_types = GetOperandTypes(instruction, instruction_bytes)
        operands = []
        if operand_types != None:
            operands = zip(operand_types, GetOperands(instruction,
                instruction_bytes))

        return instruction, 2, operands 

    def perform_get_instruction_info(self, data, addr):
        instruction, length, operands = self.decode_instruction(data, addr)
        if instruction is None:
            return None

        result = InstructionInfo()
        result.length = length
        if instruction.startswith('BR'):
            result.add_branch(TrueBranch, addr + length + (2 * operands[0][1]))
            result.add_branch(FalseBranch, addr + length)
        elif instruction.startswith('JMP'):
            result.add_branch(UnconditionalBranch, operands[0][1])
        elif instruction == 'JSR':
            result.add_branch(UnconditionalBranch, addr + operands[0][1])
        elif instruction in ['JSRR', 'TRAP']:
            result.add_branch(CallDestination, operands[0][1])
        elif instruction in ['RET', 'RTI']:
            result.add_branch(FunctionReturn)

        return result

    def perform_get_instruction_text(self, data, addr):
        instruction, length, operands = self.decode_instruction(data, addr)
        if instruction is None:
            return None

        tokens = []
        tokens.append(InstructionTextToken(InstructionToken, '%-8s' %
            instruction))

        first_iteration = True
        for operand_type, operand in operands:
            if not first_iteration:
                tokens.append(InstructionTextToken(OperandSeparatorToken, ', '))
            if operand_type in [TYPE_DR, TYPE_SR, TYPE_BR]:
                tokens.append(InstructionTextToken(RegisterToken, 'R%d' %
                    operand))
            elif operand_type in [TYPE_IMM, TYPE_REG_OFFSET, TYPE_TRAPVECT]:
                tokens.append(InstructionTextToken(TextToken, '#'))
                tokens.append(InstructionTextToken(IntegerToken, '%d' %
                    operand, operand))
            elif operand_type == TYPE_PC_OFFSET:
                addr = addr + length + (2 * operand)
                tokens.append(InstructionTextToken(PossibleAddressToken,
                    '%#x' % addr, addr))
            else:
                print 'Unknown operand type: %d' % operand_type
            first_iteration = False

        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        return None

LC3.register()
