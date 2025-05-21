use cpp_demangle::Symbol;
use memmap2::Mmap;
use object::{Object, ObjectSymbol};
use std::{borrow::Cow, collections::BTreeMap, fs, ops::Deref, path::Path};

#[derive(Debug)]
pub struct MappedFile {
    _file: fs::File,
    mmap: Mmap,
}

impl MappedFile {
    /// Opens a memory mapped file.
    ///
    /// # Safety
    ///
    /// Undefined behavior can happen if the file is modified while it is memory mapped.
    /// Read more at [Mmap docs][Mmap].
    ///
    /// # Panics
    ///
    /// This function will panic if path does not already exist or file can't be opened.
    unsafe fn new<P: AsRef<Path>>(path: P) -> Self {
        let file = fs::File::open(path).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
        Self { _file: file, mmap }
    }
}

impl Deref for MappedFile {
    type Target = Mmap;

    fn deref(&self) -> &Self::Target {
        &self.mmap
    }
}

#[derive(Debug)]
pub struct ModuleFile<'a> {
    object: object::File<'a, &'a [u8]>,
}

impl<'a> ModuleFile<'a> {
    /// Load module (object) file from given bytes.
    ///
    /// # Panics
    ///
    /// This function will panic if the object file parsing fails.
    pub fn new(bytes: &'a [u8]) -> Self {
        let object = object::File::parse(bytes).unwrap();
        Self { object }
    }

    /// Returns first function name with the given address.
    ///
    /// # Panics
    ///
    /// This function will panic if the symbol name is non UTF-8.
    pub fn function_name(&self, address: u64) -> Option<String> {
        for symbol in self.object.symbols() {
            if address != symbol.address() {
                continue;
            }
            let name = symbol.name().unwrap();
            let sym = Symbol::new(name);
            if let Err(_) = sym {
                return Some(name.into());
            }
            let sym = sym.unwrap();
            let name = sym.to_string();
            return Some(name);
        }
        None
    }

    /// Returns all function (symbol) names.
    ///
    /// # Panics
    ///
    /// This function will panic if any symbol name is non UTF-8.
    pub fn read_symbol_names(&self) -> SymbolNames {
        let mut map: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for symbol in self.object.symbols() {
            let name = symbol.name().unwrap();
            let sym = Symbol::new(name);
            let name = match sym {
                Err(_) => name.to_string(),
                Ok(sym) => sym.to_string(),
            };

            let address = symbol.address();
            let prev = map.entry(address).or_default();
            prev.push(name);
        }
        SymbolNames::new(map)
    }
}

#[derive(Debug)]
pub struct SymbolNames {
    inner: BTreeMap<u64, Vec<String>>,
}

impl SymbolNames {
    fn new(inner: BTreeMap<u64, Vec<String>>) -> Self {
        Self { inner }
    }

    /// Returns symbol name if there's only one symbol name for given address
    pub fn get_one(&self, address: u64) -> Option<&str> {
        let names = self.inner.get(&address);
        let names = if let Some(names) = names {
            names
        } else {
            return None;
        };

        if names.len() > 1 {
            None
        } else {
            Some(&names[0])
        }
    }

    /// Returns first symbol name and adds a prefix if there are more than one symbol
    /// name for a given address.
    pub fn get_prefixed<'a>(&'a self, address: u64) -> Option<Cow<'a, str>> {
        let names = self.inner.get(&address);
        let names = if let Some(names) = names {
            names
        } else {
            return None;
        };

        if names.len() > 1 {
            Some(Cow::Owned(format!("* {}", names[0])))
        } else {
            Some(Cow::Borrowed(&names[0]))
        }
    }
}

impl Deref for SymbolNames {
    type Target = BTreeMap<u64, Vec<String>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub fn run(path: &str) {
    let mapped_file = unsafe { MappedFile::new(path) };
    let module = ModuleFile::new(&**mapped_file);

    let address = 52197888;
    // let name = module.function_name(address);
    let symbols = module.read_symbol_names();
    let name = symbols.get_prefixed(address);
    // let names = symbols.get(&address).unwrap();
    println!("{:?}", name);
}
