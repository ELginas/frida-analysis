use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_hex::{CompactPfx, SerHex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ModuleMemory {
    name: String,
    #[serde(with = "SerHex::<CompactPfx>")]
    base: u64,
    size: u64,
    path: String,
}

impl ModuleMemory {
    pub fn in_range(&self, address: u64) -> bool {
        self.base <= address && address <= self.base + self.size
    }

    /// # Panics
    ///
    /// This function will panic if address is not in bounds.
    pub fn offset(&self, address: u64) -> u64 {
        assert!(self.in_range(address));
        address - self.base
    }

    pub fn module_address(&self, offset: u64) -> ModuleAddress {
        assert!(self.in_range(offset));
        ModuleAddress::new(&self, offset)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct ModuleMap {
    modules: Vec<ModuleMemory>,
}

impl ModuleMap {
    pub fn new(modules: Vec<ModuleMemory>) -> Self {
        Self { modules }
    }

    pub fn find_address(&self, address: u64) -> Option<&ModuleMemory> {
        self.modules.iter().find(|module| module.in_range(address))
    }

    pub fn get_module_address(&self, address: u64) -> Option<ModuleAddress> {
        let module = self.find_address(address);
        match module {
            Some(module) => {
                let offset = module.offset(address);
                Some(ModuleAddress::new(module, offset))
            }
            None => None,
        }
    }
}

impl Deref for ModuleMap {
    type Target = Vec<ModuleMemory>;

    fn deref(&self) -> &Self::Target {
        &self.modules
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleAddress<'a> {
    module: &'a ModuleMemory,
    offset: u64,
}

impl<'a> ModuleAddress<'a> {
    fn new(module: &'a ModuleMemory, offset: u64) -> Self {
        Self { module, offset }
    }

    pub fn module(&self) -> &ModuleMemory {
        &self.module
    }

    pub fn offset(&self) -> &u64 {
        &self.offset
    }
}
