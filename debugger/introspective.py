from mechanic import *
from ctypes import *
import subprocess
import sys
import os

breakpoints = []


# Check OS
if os.name == 'nt':
	print('[!] This code is not designed for Windows :(')
	exit()

def load_syscalls():
	if not os.path.isfile('utility/syscalls.txt'):
		print('[!] Missing syscall.txt?'); exit(1)

	SYSCALLS = {}
	for line in open('utility/syscalls.txt','r').readlines():
		fields = line.split('\t')
		name = fields[1]
		source = fields[2]
		ebx_val = fields[3]
		ecx_val = fields[4]
		edx_val = fields[5]
		esx_val = fields[6]
		edi_val = fields[7]
		syscall = int(fields[0])
		operation = {'name': name, 'source': source, 'ebx': ebx_val,
					 'ecx':	ecx_val, 'edx': edx_val, 'esx': esx_val,
					 'edi': edi_val}
		SYSCALLS[syscall] = operation
	return SYSCALLS

# Load libraries
if not os.path.isfile('poker.so') and os.path.isfile('deltalib.c'):
	os.system('gcc -shared -fPIC deltalib.c -o poker.so')

tracelib = cdll.LoadLibrary('./poker.so')
syscalls = load_syscalls()

class Command(Structure):
    _fields_ = [("file",c_char_p),  ("args",c_char_p)]

def swap(filename, destroy):
	data = []
	for line in open(filename, 'r').readlines():
		data.append(line.replace('\n',''))
	if destroy:
		os.remove(filename)
	return data

def launch_program(program_file):
	args = [program_file]
	if len(sys.argv) > 3:
		for extra_arg in sys.argv:
			args.append(extra_arg)
	return subprocess.Popen(args)

def restart_process(pid):
	os.system(f'kill -RESTART {pid}')
	return

def check_args():
	args = b'Testing123!'
	if len(sys.argv) < 2:
		print(f'Usage: {sys.argv[0]} [program]')
		exit(1)
	else:
		if not os.path.isfile(sys.argv[1]):
			print(f'[!] unable to find {sys.argv[1]}')
			exit(1)
		if len(sys.argv) > 2:
			args = bytes(argv[1])
		return sys.argv[1], args

def step_through_syscall(pid):
	tracelib.enter_syscall(pid)
	N = tracelib.show_syscall_args(pid)
	if N in syscalls.keys():
		EBX = tracelib.get_rbx(pid)
		msg = f'{syscalls[N]["name"]}({EBX},{syscalls[N]["ecx"]}'
		msg +=f'{syscalls[N]["edx"]},{syscalls[N]["edx"]},{syscalls[N]["esx"]}'
		msg += syscalls[N]["edi"].replace("\n","") + ')'
		# testing: 
		print()
		print(f'\033[1m = \033[31m[{msg}]\033[0m')
	tracelib.process_syscall(pid)
	tracelib.last_syscall_result(pid)

def read_registers(pid):
	registers = {'RAX':tracelib.get_rax(pid),
				 'RBX':tracelib.get_rbx(pid),
				 'RCX':tracelib.get_rcx(pid),
				 'RDX':tracelib.get_rdx(pid),
				 'RIP':tracelib.get_rip(pid),
				 'RSI':tracelib.get_rsi(pid),
				 'RBP':tracelib.get_rbp(pid),
				 'RSP':tracelib.get_rsp(pid)}
	return registers

def show_registers(pid):
	banner = '='*20
	row = ''
	col = 1
	registers = read_registers(pid)
	for reg in registers.keys():
		row += f'| {reg}:  {"{0:#0{1}x}".format(registers[reg],12)}  '
		if col % 3 == 0:
			row += '|\n'
		col +=1
	print(f'{banner}| REGISTERS |{banner}')
	print(f'{row}')

def diff_registers(state1, state2):
	banner = '='*30
	row = ''
	col = 1
	diffs = {}
	for reg in list(state1.keys()):
		if state1[reg] != state2[reg]:
			value = "{0:#0{1}x}".format(state2[reg],12)
			row += f'| {reg}:  \033[1m\033[31m{value}  \033[0m'
		else:
			row += f'| {reg}:  {"{0:#0{1}x}".format(state2[reg],12)}  '
		if col % 3 == 0:
			row += '|\n'
		col +=1
	print(f'{banner}| REGISTERS |{banner}')
	print(f'{row}')


def read_process_memory(pid):
	address = int(input('\tEnter Offset to Read: '), 16)
	print(f'Trying to read 0x{hex(address)}')
	tracelib.read_data_from_memory(address)

def add_break_point(pid):
	breakpoints.append(int(input('Enter Address:'),16))
	print(f'Breakpoints: {breakpoints}')

def dump_strings(pid):
	target = sys.argv[1].split('/')[-1]
	strings_found = explore_strings(target)
	print(f'[+] {len(strings_found)} in {target}')
	for i in range(len(strings_found)):
		print(f'  [{i}] {strings_found[i]}')
	return strings_found

def disassembly(pid):
	target = sys.argv[1].split('/')[-1]
	disass = disassemble(target)
	print(f'[+] {len(disass.keys())} instructions disassembled from {target}')
	return disass

def show_help(pid):
	print('======== :: Δ HELP MENU Δ :: ======== ')
	print('- [c] Continues through rest of program')
	print('- [stepi] Single Step to next instruction')
	print('- [firecracler] run each instruction in the program one by one')
	print('- [registers] Dump')
	print('- [next] Step through to next syscall')
	print('- [read-mem] Read memory at address')
	print('- [stack-view] Try to read stack memory')
	print('- [strings] dump strings found in binary')
	print('- [objdump] provides crude disassembly of binary')
	print('- [add-break] Add breakpoint at hex address')
	print('- [restart] End process and restart it')
	print('- [help] Show this menu')
	print('- [q] Quit')
	print('======================================')

def explore_stack(pid):
	pid = int(input('(re-enter pid):'))
	# try to be root maybe? 
	os.system(f'gnome-terminal -- sh -c "bash ./follow.sh {pid}"')

def modify_heap(pid, offset):
	# open memfile 
	memfile = f'/proc/{pid}/mem'

def auto_step(pid):
	stepping = True
	last_registers = read_registers(pid)
	try:
		while stepping:
			current_regs = read_registers(pid)
			diff_registers(last_registers, current_regs)
			last_registers = current_regs
			stepping = tracelib.step(pid)

	except KeyboardInterrupt:
		stepping = False
		pass

def main():
	newpid = os.fork()
	# check args
	target_program = Command()
	program, args = check_args()
	target_program.file = bytes(program,'ascii')
	target_program.args = args
	N = 0
	first = True
	################ DEFINE DEBUGGER OPERATIONS ################ 
	operations = {'c': tracelib.continue_pid,
				  'continue':tracelib.continue_pid,
				  'stepi': tracelib.step,
				  'registers': tracelib.show_registers,
				  'next': step_through_syscall,
				  'help': show_help,
				  'stack-view': explore_stack,
				  'add-break': add_break_point,
				  'read-mem': read_process_memory,
				  'strings': dump_strings,
				  'objdump': disassembly,
				  'restart': restart_process,
				  'firecracker': auto_step,
				  'q': exit,'quit': exit}

	################ << Δ Run Delta-Shell Δ >> ################ 
	while True:
		if newpid == 0:
			# execute program to examine
			if first:
				print('='*80)
				tracelib.zero_ptrace()
				debugee = tracelib.launch_program(byref(target_program))
				first = False
		# In parent
		elif newpid != -1:
			# Need to halt program for letting user choose what happens next
			if first:
				# so wait for child to start 
				tracelib.wait_up(newpid)
				first = False
				tracelib.pause_pid(newpid)
				print(f'[Δ] DEBUGEE PID:')
				cmd = f'echo $(pidof {target_program.file[2:].decode()})'
				query = subprocess.Popen(['/bin/sh','-c',cmd])
				debugee = int(query.wait(3))
				print(f'[Δ] Pausing {target_program.file} for user control')
			
			# Check if rsp matches any breakpoints!
			RSP = tracelib.get_rsp(newpid)
			# TODO: Debugging the debugger breakpoint feature
			print(f'[DEBUG] RSP: {hex(RSP)}')
			for breakpt in breakpoints:
				if breakpt == hex(RSP):
					print(f'[Δ:: Hit Breakpoint {hex(RSP)}]')
					tracelib.pause_pid(newpid)

			################ Δ Process User Input Δ ################ 
			command = str(input('\033[1mΔ\033[35m:shell>>\033[0m '))
			if command in operations.keys():
				operations[command](newpid)
			else:
				print(f'\033[1mUnrecognized Command \033[33m{command}\033[0m')
			
			


if __name__ == '__main__':
	main()
