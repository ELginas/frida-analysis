from pathlib import Path
from elftools.elf.elffile import ELFFile

# filepath = "/home/user/projects/frida-examples/src/a.out"
# filepath = "/usr/bin/btm"
# Note: just iterating CU names takes 27s and iterating over DW_TAG_subprogram is feasible for specific CUs only due to time.
filepath = "/home/user/GithubRepos/godot/bin/godot.linuxbsd.editor.x86_64.debugsymbols"


def attribute_str(DIE, attribute_name):
    if attribute_name in DIE.attributes:
        return DIE.attributes[attribute_name].value.decode('utf-8')


def attribute_num(DIE, attribute_name):
    if attribute_name in DIE.attributes:
        return DIE.attributes[attribute_name].value


def attribute_hex(DIE, attribute_name):
    value = attribute_num(DIE, attribute_name)
    if value:
        return hex(value)


def process_CU(CU):
    top_DIE = CU.get_top_DIE()
    cu_name = Path(top_DIE.get_full_path()).as_posix()
    # if cu_name.endswith("<artificial>"):
    # if not cu_name == "/home/user/GithubRepos/godot/main/main.cpp":
    # if not cu_name == "/home/user/GithubRepos/godot/modules/multiplayer/multiplayer_spawner.cpp":
    #     print(f'Skipping {cu_name}')
    #     return

    print(cu_name)
    process_DIE(top_DIE)


def process_DIE(DIE):
    if DIE.tag == "DW_TAG_subprogram":
        name = attribute_str(DIE, "DW_AT_name")
        low_pc = attribute_hex(DIE, "DW_AT_low_pc")
        high_pc = attribute_hex(DIE, "DW_AT_high_pc")
        object_pointer = attribute_hex(DIE, "DW_AT_object_pointer")
        linkage_name = attribute_str(DIE, "DW_AT_linkage_name")

        search_hexes = ["0x30f1aa0", "0x31f1aa0"]
        values = {
            'low_pc': low_pc,
            'high_pc': high_pc,
            'object_pointer': object_pointer
        }
        for search_hex in search_hexes:
            for key in values:
                value = values[key]

                if search_hex == key:
                    print('Match:', search_hex, value)
                    print(DIE)
        # print(name, low_pc, high_pc, object_pointer, linkage_name)
        # print(DIE)
        # if name and low_pc:
        #     print(name, low_pc, high_pc)
    for child in DIE.iter_children():
        process_DIE(child)


def run(filepath):
    file = open(filepath, 'rb')
    print('Processing file:', filepath)
    elffile = ELFFile(file)

    dwarfinfo = elffile.get_dwarf_info()
    CUs = [CU for CU in dwarfinfo.iter_CUs()]
    if len(CUs) == 0:
        print("No DWARF entries.")
        return

    for CU in CUs:
        process_CU(CU)


run(filepath)
