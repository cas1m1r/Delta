import random
import string
import sys
import os

letters = list(string.ascii_lowercase + string.ascii_uppercase)

def random_filename(ext):
	return f'{"".join(random.sample(letters, 6))}.{ext}'

def cmd(command, verbose):
	tmpf = random_filename('txt')
	os.system(f'{command} > {tmpf}')
	result = open(tmpf, 'r').read()
	os.remove(tmpf)
	return result

def swap(filename, destroy):
	data = []
	for line in open(filename, 'r').readlines():
		data.append(line.replace('\n',''))
	if destroy:
		os.remove(filename)
	return data


def get_maps_file(pid):
	mapdata = {}
	for line in open(f'/proc/{pid}/maps','r').readlines():
		try:
			fields = line.replace('\n','').split(' ')
			offsets = fields[0].replace('\n','').split('-')
			perms = fields[1].replace('\n','')
			label = fields[-1].replace('\n','')
			mapdata[label] = [int(offsets[0],16), int(offsets[1],16)]
		except IndexError:
			pass
	return mapdata

def dumpstack(mapdata, pid):
	stack_start = mapdata['[stack]'][0]
	stack_stops = mapdata['[stack]'][1]
	stack_range = stack_stops - stack_start
	
	try:
		memfile = open(f'/proc/{pid}/mem','rb+')
	except:
		print(f'[!] Cant open /proc/{pid}/mem')
		print('Are you root?')
		return []
	memfile.seek(stack_start)
	stack_data = memfile.read(stack_range)
	memfile.close()
	# print(f'[+] {len(stack_data)} bytes read from /proc/{pid}/mem')
	return stack_data.replace(b'\x00',b'')


def main():
	if len(sys.argv) > 1:
		mapdata = get_maps_file(sys.argv[1])
		print(dumpstack(mapdata, sys.argv[1]))
	else:
		print(f'Usage: {sys.argv[0]}')
		exit()

if __name__ == '__main__':
	main()