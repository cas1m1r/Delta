#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/reg.h> 
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <assert.h>
#include <wchar.h>
#define _OPEN_SYS_ITOA_EXT


/* define a structure that will be passed from python */
struct PyStruct {
	const char* file;
	const char* argv;
};


// convenience macro for printing error messages
#define ERR(...)\
	do{\
		printf("Δ Err: %s\n",  __VA_ARGS__);\
		fputc('\n', stderr);\
		exit(EXIT_FAILURE);\
	} while (0)

void zero_ptrace(){
	ptrace(PTRACE_TRACEME, 0, 0, 0);
	return;
}

int wait_up(int pid){
	waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    return 1;
}


void show_registers(int pid){
	struct user_regs_struct regs;
	printf("-------------------------------------------------------------------\n");
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	printf("RIP:\t0x%08llx\t", regs.rip);
	printf("RAX:\t0x%08llx\t", regs.rax);
	printf("R08:\t0x%08llx\n", regs.r8);
	printf("RCX:\t0x%08llx\t", regs.rcx);
	printf("RDX:\t0x%08llx\t", regs.rdx);
	printf("R09:\t0x%08llx\n", regs.r9);
	printf("RBX:\t0x%08llx\t", regs.rbx);
	printf("RSI:\t0x%08llx\t", regs.rsi);
	printf("R10:\t0x%08llx\n", regs.r10);
	printf("RDI:\t0x%08llx\t", regs.rdi);
	printf("RBP:\t0x%08llx\t", regs.rbp);
	printf("R11:\t0x%08llx\n", regs.r11);
	printf("SS:\t0x%08llx\t", regs.ss);
	printf("RSP:\t0x%08llx\t", regs.rsp);
	printf("CS:\t0x%08llx\n", regs.cs);
	printf("-------------------------------------------------------------------\n");
	return;
}

void enter_syscall(int pid){
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
		ERR("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1)
    	ERR("%s", strerror(errno));
    return;
}

void read_data_from_memory(long* p){
	printf("[%p]\t0x%08x\t0x%08x", p, p, &p);
	return;
}

void pause_pid(int pid){
	// int64_t prev_rsp = 0x0;
	// struct user_regs_struct tmpregs;
	// ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	// prev_rsp = tmpregs.rsp;
	// tmpregs.rsp = tmpregs.rsp & 0xcc0000000000;
	// ptrace(PTRACE_SETREGS, pid, 0, &tmpregs);
   	ptrace(PTRACE_INTERRUPT, pid ,0, 0);
   	return;
}

void launch_program(const struct PyStruct* s){
	printf("Δ::Launching->%s\n", s->file);
	execvp(s->file, s->argv); // I hope this works
 	ERR("%s", strerror(errno));
}

int show_syscall_args(int pid){
	  struct user_regs_struct regs;
       if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
           ERR("%s", strerror(errno));
       long syscall = regs.orig_rax;

        /* Print a representation of the system call */
        fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);
        return (int) syscall;
}

void process_syscall(int pid){
	/* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            ERR("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            ERR("%s", strerror(errno));
}

void last_syscall_result(int pid){
	// get regs 
	struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        ERR("%s", strerror(errno));
	/* Get system call result */
 	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        fputs(" = ?\n", stderr);
        if (errno == ESRCH)
            exit(regs.rdi); // system call was _exit(2) or similar
        ERR("%s", strerror(errno));
    }

    /* Print system call result */
    fprintf(stderr, " = %ld\n", (long)regs.rax);
}

bool step(int pid){
	bool stepped = true;
	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0){
		perror("ptrace");
		stepped = false;
	}
	return stepped;
}

void exec_next_syscall(int pid){
	/* Run system call and stop on exit */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, 0, 0);
}

bool continue_pid(int pid){
	bool completed = true;
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
		perror("ptrace");
		completed = false;
	}
	return completed;
}

bool check_breakpoint(int pid, int n, char *point, char *breakpoints[]){
	bool isBreakpoint = false;
	for (int i =0; i < n; i++){
		if (strcmp(breakpoints[i], point)==0)
			isBreakpoint = true;
			break;
	}
	return isBreakpoint;
}

void set_registers(int pid, struct user_regs_struct new_regs){
	ptrace(PTRACE_SETREGS, pid, 0, &new_regs);
}

unsigned long get_rax(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rax;
}

unsigned long get_rip(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rip;	
}

unsigned long get_rcx(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rcx;
}

unsigned long get_rdx(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rdx;
}

unsigned long get_rbx(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rbx;
}

unsigned long get_rsi(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rsi;
}

unsigned long get_rbp(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rbp;
}

unsigned long get_rdi(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rdi;
}

unsigned long get_rsp(int pid){
	// Use Ptrace to get state of registers for given PID
	struct user_regs_struct tmpregs;
	ptrace(PTRACE_GETREGS, pid, 0, &tmpregs);
	return tmpregs.rsp;
}