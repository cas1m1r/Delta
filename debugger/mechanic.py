from seeker import swap, cmd, random_filename
import random
import string
import time 
import sys 
import os

letters = list(string.ascii_lowercase + string.ascii_uppercase)

def disassemble(fname, verbose):
	disass = {'functions': {},'asm': {}}
	dump = cmd(f'objdump -D {fname}', False)
	for line in dump.split('\n'):
		try:
			fields = line.split('\t')
			offset = int(fields[0].split(':')[0].replace(' ',''),16)
			instructions = ' '.join(fields[-2:])
			disass['asm'][offset] = instructions
		except ValueError:
			pass
		if line.find('<.')>0 and line.find('>:')>0:
			fcname = line[line.find('<.')+1:line.find('>:')]
			offset = int(line.split(' ')[0],16)
			if verbose:
				print(f'[+] Found {fcname} at {hex(offset)}')
			disass['functions'][fcname] = offset
		elif line.find('<_')>0 and line.find('>:')>0:
			fcname = line[line.find('<')+1:line.find('>:')]
			offset = int(line.split(' ')[0],16)
			if verbose:
				print(f'[+] Found {fcname} at {hex(offset)}')
			disass['functions'][fcname] = offset
		#TODO: should also know when the function ends
	return disass

def see_asm_range(dis, start, stop, verbose):
	snippet = ''
	if start in dis['asm'].keys() and stop in dis['asm'].keys():
		for offset in dis['asm']:
			if start <= offset <= stop:
				snippet += dis['asm'][offset]
				print(dis['asm'][offset])
	return snippet
