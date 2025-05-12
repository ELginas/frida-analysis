use cpp_demangle::Symbol;
use object::{Object, ObjectSymbol};
use std::fs;

pub fn run(path: &str) {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();

    let address = 53688592;

    for symbol in object.symbols() {
        if address != symbol.address() {
            continue;
        }
        let name = symbol.name().unwrap();
        let sym = Symbol::new(name).unwrap();
        let name = sym.to_string();
        println!("{} - {}: {:x?}", symbol.index(), name, symbol);
    }
}
