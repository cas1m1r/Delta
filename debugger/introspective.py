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
	# check for laststack.txt, if exists process it 
	# now replace it with new stack
	# stackscope.check_stack_for_changes(pid)
	# check for any interesting differences


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




def main():
	newpid = os.fork()
	# check args
	target_program = Command()
	program, args = check_args()
	target_program.file = bytes(program,'ascii')
	target_program.args = args
	N = 0
	first = True
	
	operations = {'c': tracelib.continue_pid,'continue':tracelib.continue_pid,
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
				  'q': exit,'quit': exit}

	# Run Delta-Shell
	while True:
		if newpid == 0:
			# execute program to examine
			if first:
				print('='*80)
				tracelib.zero_ptrace()
				debugee = tracelib.launch_program(byref(target_program))
				# Test it works 
				print('Initial Registers:')
				tracelib.show_registers(debugee)
				print('='*80)
				first = False

		elif newpid != -1:
			# Need to halt program for letting user choose what happens next
			if first:
				# in parent, so wait for pid, 
				tracelib.wait_up(newpid)
				first = False
				tracelib.pause_pid(newpid)
				print(f'[Δ] PID:')
				query = subprocess.Popen(['/bin/sh','-c',f'echo $(pidof {target_program.file[2:].decode()})'])
				debugee = int(query.wait(3))
				print(f'[Δ] Pausing {target_program.file} for user control')
			command = str(input('\033[1mΔ\033[35m:shell>>\033[0m '))
			if command in operations.keys():
				operations[command](newpid)
			else:
				print(f'\033[1mUnrecognized Command \033[33m{command}\033[0m')
			# TODO: Check if rsp matches any breakpoints!
			RSP = tracelib.get_rsp(newpid)
			for breakpt in breakpoints:
				if breakpt == hex(RSP):
					print(f'[Δ:: Hit Breakpoint {hex(RSP)}]')
					tracelib.pause_pid(newpid)
			


if __name__ == '__main__':
	main()
