# unicorn_examples
[+] on simple_x86_shellcode, we just;
  - init an uc_engine handle
  - map a memory space for it
  - write code to be executed to that memory space
  - uc_emu_start() does the rest
  - get and update registers value by uc_reg_read/write
  - set a hook to get each instructions opcode and instruction size, seem like a simple linear disassembler
    
[+] on shellcode_pe_emulate, we're: get code to be emulated from an input file

[+] TODO:
  - interrups, CPU exceptions
  - registers, flags state (debugger - oriented)
  - get and emulate instructions from .text section of a PE file
