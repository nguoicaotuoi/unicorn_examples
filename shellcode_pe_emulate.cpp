// get code to be emulated from an input file

/*
TODO:
	Get and emulate instructions from .text section of a PE file by;
	- read PE file to BuffImage
	  PIMAGE_NT_HEADERS			NtHeaders=(PIMAGE_NT_HEADERS)(PCHAR(BuffImage) + PIMAGE_DOS_HEADER(BuffImage)-> e_lfanew);
	  PIMAGE_SECTION_HEADER		psText = IMAGE_FIRST_SECTION(NtHeaders);
	  int						posRawOffset;
	  int						posRVA;

	  for(int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++){
		  if(!strcmp((char*)psText[i].Name, ".text")){
			  posRVA = psText[i].VirtualAddress;
			  posRawOffset = psText[i].PointerToRawData;
		  }
	  }
*/

#include <unicorn/unicorn.h>
#include <stdio.h>


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

static void emulate(char* SHELL_CODE)
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

int main(int argc, char **argv)
{
	if(argc != 2){
		printf("USAGE: simple_x86_shellcode.exe [filename]\n");
		return -1;
	}
	
	FILE *file = fopen(argv[1], "rb");
	fseek(file, 0, SEEK_END);
	long file_len = ftell(file);
	rewind(file);
	char* SHELL_CODE = (char*)malloc((file_len+1)*sizeof(char));
	fread(SHELL_CODE, file_len, 1, file);
	printf("SHELL_CODE: ");
	for(int i = 0; i < file_len; i++)
		printf("\\x%02x", SHELL_CODE[i]);
	printf("\n\n");
	fclose(file);

	emulate(SHELL_CODE);

    return 0;
}
