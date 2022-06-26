import random
import string
import os

letters = list(string.ascii_lowercase + string.ascii_uppercase)

def random_filename(ext):
	return f'{"".join(random.sample(letters, 6))}.{ext}'

def cmd(command, verbose):
	tmpf = random_filename('txt')
	os.system(f'{command} > {tmpf}')
	result = []
	for ln in open(tmpf, 'r').readlines():
		result.append(ln.replace('\n',''))
	os.remove(tmpf)
	return result

def disassemble(fname):
	disass = {}
	dump = cmd(f'objdump -D {fname}', False)
	for line in dump:
		try:
			fields = line.split('\t')
			offset = int(fields[0].split(':')[0].replace(' ',''),16)
			opcodes = fields[0].replace('    ','').split(':')[1]
			instructions = fields[-2:]
			disass[offset] = [opcodes, instructions]
		except ValueError:
			pass
	return disass

def explore_strings(fname):
	if not os.path.isfile(fname):
		print(f'[!] Cannot fine {fname}')
		return []
	else:
		return [line for line in cmd(f'strings {fname}',False)]
