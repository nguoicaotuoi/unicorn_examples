/*
we just:
	- init an uc_engine handle
	- map a memory space for it
	- write code to be executed to that memory space
	- uc_emu_start() does the rest
	- get and update registers value by uc_reg_read/write
	- set a hook to get each instructions opcode and instruction size,
	  seem like a simple linear disassembler
*/

#include <unicorn/unicorn.h>
#include <string.h>


// shellcode to be emulated, just print out "hello"
#define SHELL_CODE "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59"\
					"\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff"\
					"\xff\xff\x68\x65\x6c\x6c\x6f"
// #define SHELL_CODE "\x31\xc0\xbb\xea\x1b\xe6\x77\x66\xb8\x88\x13\x50\xff\xd3"

// prefered base address for emulation
#define BASE_ADDRESS 0x00400000

#define MIN(a, b) (a < b? a : b)
// callback for HOOK_CODE
static void disasm(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int r_eip;
    uint8_t tmp[16];

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf("%08x  ", r_eip);

    size = MIN(sizeof(tmp), size);		// instruction size
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;
        for (i = 0; i < size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
}

static void emulate(void)
{
    uc_engine *uc;
    uc_err ret_code;
    uc_hook trace;

    int r_esp = BASE_ADDRESS + 0x200000;  // ESP

    printf("Starting emulation...\n\n");

    // init the emulator
    ret_code = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (ret_code){
        printf("Failed to init emulator in X86 32-bit mode (%u - %s).\n", ret_code, uc_strerror(ret_code));
        return;
    }

    // map 5MB of memory from BASE_ADDRESS for this emulation, all permissions
	//						------> why does this emulation need so much memory?! 
    uc_mem_map(uc, BASE_ADDRESS, 5 * 1024 * 1024, UC_PROT_ALL);

    // write shellcode to be emulated to mapped memory
    if (uc_mem_write(uc, BASE_ADDRESS, SHELL_CODE, sizeof(SHELL_CODE) - 1)){
        printf("Failed to write instructions to memory.\n");
        return;
    }

    // update related registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

    // linear sweep disassembly
    uc_hook_add(uc, &trace, UC_HOOK_CODE, disasm, NULL, 1, 0);
	
	/*
	TODO:
		 - interrups, CPU exceptions
		 - registers, flags state (debugger - oriented)
	*/ 

    // start the emulation
    ret_code = uc_emu_start(uc, BASE_ADDRESS, BASE_ADDRESS + sizeof(SHELL_CODE) - 1, 0, 0);
    if (ret_code){
        printf("Failed on uc_emu_start() (%u - %s).\n",
                ret_code, uc_strerror(ret_code));
    }

    printf("\nEmulation done.\n");

    uc_close(uc);
}

int main()
{
    printf("SHELL_CODE: ");
	for(int i = 0; i < sizeof(SHELL_CODE); i++)
		printf("\\x%02x", SHELL_CODE[i]);
	printf("\n\n");

	emulate();
    
    return 0;
}
