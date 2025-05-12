use cpp_demangle::Symbol;
use indexmap::IndexMap;
use itertools::Itertools;
use object::{Object, ObjectSymbol};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fs::{self, read_to_string},
    path::Path,
};

use anyhow::Context;

pub fn read_json<P: AsRef<Path>>(path: P, module: &str) -> anyhow::Result<BTreeMap<u64, u64>> {
    let text = read_to_string(path)?;
    let key_values: HashMap<String, serde_json::Value> = serde_json::from_str(&text)?;

    let mut map = BTreeMap::new();
    for (curr_module, functions) in key_values {
        if curr_module != module {
            continue;
        }

        let functions = functions.as_object().context("")?;
        for (function, count) in functions {
            let count = count.as_number().context("")?.as_u64().context("")?;
            let offset = function.strip_prefix("sub_").context("")?;
            let offset = u64::from_str_radix(offset, 16)?;
            map.insert(offset, count);
        }
    }
    Ok(map)
}

pub fn read_symbols<P: AsRef<Path>>(path: P) -> anyhow::Result<BTreeMap<u64, Vec<String>>> {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();

    let mut map: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for symbol in object.symbols() {
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
    Ok(map)
}

pub fn map_function_counts<'a>(
    function_counts: BTreeMap<u64, u64>,
    symbols: &BTreeMap<u64, Vec<String>>,
) -> IndexMap<Cow<'_, str>, u64> {
    let mut new_map = BTreeMap::new();
    for (offset, count) in function_counts {
        let functions = symbols.get(&offset).unwrap();
        let name = if functions.len() == 1 {
            Cow::from(&functions[0])
        } else {
            Cow::from(format!("* {}", functions[0]))
        };
        new_map.insert(name, count);
    }
    new_map
        .into_iter()
        .sorted_by(|&(_, a), &(_, b)| b.cmp(&a))
        .collect()
}
