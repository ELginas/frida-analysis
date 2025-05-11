# DWARF

Compile ELF file with debug symbols:

```sh
gcc file.c -g
```

And DWARF info should be located in `.debug_info` section tho `.debug_*` sections are generated too. Check with:

```sh
objdump -x a.out
```

And here's the DWARF 5 spec: https://dwarfstd.org/doc/DWARF5.pdf
