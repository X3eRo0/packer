import pefile
import sys
import struct
import subprocess
from optparse import OptionParser

def build_parser():
	usage = 'usage: %prog [options]'
	parser = OptionParser(usage)
	parser.add_option('-i','--input',dest='input',help='input file')
	parser.add_option('-o','--output',default='a.xvm',dest='output',help='output file')
	parser.add_option('-k','--key',default='0x41',dest='key',help='single byte key')
	return parser

def info(pe):

	print "Magic:\t\t\t", hex(pe.DOS_HEADER.e_magic)[2:].decode('hex')[::-1]
	print "ImageBase:\t\t", hex(pe.OPTIONAL_HEADER.ImageBase)
	print "SizeOfCode:\t\t", hex(pe.OPTIONAL_HEADER.SizeOfCode)
	print "EntryPoint:\t\t", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	print "BaseOfCode:\t\t", hex(pe.OPTIONAL_HEADER.BaseOfCode)
	print "{} VA:\t\t".format(pe.sections[-1].Name), hex(pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress)
	print "new_sec:\t\t",    hex(pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress)
	print "jmp_loc:\t\t", 	 hex(pe.OPTIONAL_HEADER.ImageBase+pe.sections[0].VirtualAddress)

def encrypt(data, key):

	data = bytearray(data)
	for i in xrange(len(data)):
		data[i] ^= key

	return data

def pack(jmp):
	return '\xB8' + struct.pack("<I", jmp) + '\xFF\xD0\xE9'

def obfuscate(jmp):
	return '\xE9' + struct.pack("<I",jmp)

def gen_loader(new_sec,jmp_loc, clength, xlength, key, oep):
	

	skip = new_sec - jmp_loc + 0x200 + 3

	loader = [
		'use32\n',
		'pop esi\n',
		'add esi, {}\n'.format(hex(skip)),
		'push esi\n',
		'jmp ret_\n'
		'mov si, si\n',
		'mov esp, ebp\n',
		'xchg edi, esi\n',
		'mov cl, cl\n',
		'xchg esi, edi\n',
		'mov di, di\n',
		'cpuid\n',
		'mov ebx, AAAAAAA0\n',
		'mov edx, AAAAAAA1\n',
		'mov ecx, AAAAAAA2\n',
		'copy_loop:\n',
		'\tmov al, [ebx]\n',
		'\tmov [edx], al\n',
		'\tcmp ecx, 0\n',
		'\tjz end_copy_loop\n',
		'\tdec ebx\n',
		'\tdec edx\n',
		'\tdec ecx\n',
		'\tjmp copy_loop\n',
		'end_copy_loop:\n',
		'\tmov ebx, AAAAAAA3\n',
		'\tmov ecx, AAAAAAA4\n',
		'xor_loop:\n',
		'\tmov al, byte [ebx]\n',
		'\txor al, AAAAAAA5\n',
		'\tmov byte [ebx], al\n',
		'\tcmp ecx, 0\n',
		'\tjz stop_loop\n',
		'\tdec ebx\n',
		'\tdec ecx\n',
		'\tjmp xor_loop\n',
		'stop_loop:\n',
		'\tpush AAAAAAA6\n',
		'ret_:\n',
		'\tlea   esp, [esp+8]\n',
		'\tjmp   dword[esp-8]\n',
		]
	

	data = ""
	for i in loader:
		data += i

	data = data.replace("AAAAAAA0", hex(new_sec + clength - 1))
	data = data.replace("AAAAAAA1", hex(jmp_loc + clength - 1))
	data = data.replace("AAAAAAA2", hex(clength - 1))
	data = data.replace("AAAAAAA3", hex(jmp_loc+xlength-1))
	data = data.replace("AAAAAAA4", hex(xlength-1))
	data = data.replace("AAAAAAA5", hex(key))
	data = data.replace("AAAAAAA6", hex(oep))



	return data

def main(argc, argv):


	if(argc < 2):
		print "Usage: ./packer <target EXE>"
		exit()

	parser = build_parser()
	(options, args) = parser.parse_args()

	input = options.input
	output = options.output
	key = int(options.key, 16)
	print "Key:\t\t\t",hex(key)

	pe = pefile.PE(options.input)
	pe.add_last_section(size=1024)
	pe.sections[0].xor_data(key)
	pe.data_copy(pe.sections[0].PointerToRawData, pe.sections[-1].PointerToRawData, 0x200)
	oep = pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint
	open('asm.asm', 'w').write(
		gen_loader(
			pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress,
			pe.OPTIONAL_HEADER.ImageBase+pe.sections[0].VirtualAddress,
			0x200,
			pe.sections[0].Misc_VirtualSize,
			key,
			oep)
		)
	subprocess.check_output(['.\\FASM.EXE', 'asm.asm'])
	loaded = open("asm.bin", "rb").read()
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[0].VirtualAddress
	pe.set_bytes_at_offset(pe.sections[0].PointerToRawData, pack(pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress + 0x200))
	pe.set_bytes_at_offset(pe.sections[-1].PointerToRawData + 0x200, loaded)
	pe.sections[0].Characteristics  |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
	#pe.sections[-1].Characteristics  |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
	pe.write(filename=output)
	info(pe)


if __name__ == "__main__":
	main(len(sys.argv), sys.argv)