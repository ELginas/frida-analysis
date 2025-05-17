use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::read_to_string,
    path::Path,
};

use anyhow::{Context, bail};
use dwarf_parsing::discoverer::{DiscovererJson, ModuleMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target<'a> {
    pub module: &'a ModuleMetadata,
    pub offset: u64,
}

impl<'a> Target<'a> {
    pub fn new(module: &'a ModuleMetadata, offset: u64) -> Self {
        Self { module, offset }
    }
}

fn hex_to_num(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).ok()
}

fn get_resolved_locations<P: AsRef<Path>>(path: P) -> anyhow::Result<HashMap<u64, u64>> {
    let text = read_to_string(path)?;
    let resolved_locations: HashMap<String, String> = serde_json::from_str(&text)?;
    let resolved_locations = resolved_locations
        .into_iter()
        .map(|(k, v)| {
            let k = hex_to_num(&k);
            let v = hex_to_num(&v);
            match (k, v) {
                (Some(k), Some(v)) => Some((k, v)),
                _ => None,
            }
        })
        .collect::<Option<HashMap<_, _>>>()
        .context("")?;
    Ok(resolved_locations)
}

fn main() -> anyhow::Result<()> {
    let data_path = "../data/discoverer4.json";
    let resolved_locations_path = "../data/resolved_functions.json";
    let binary_module = "godot.linuxbsd.editor.x86_64";

    let text = read_to_string(data_path)?;
    let data: DiscovererJson = serde_json::from_str(&text)?;

    let resolved_functions = get_resolved_locations(resolved_locations_path)?;

    let module = data
        .modules
        .into_iter()
        .find(|module| module.name == binary_module)
        .unwrap();

    let module_functions = data
        .functions
        .into_iter()
        .filter(|&(location, _)| module.in_range(location))
        .map(|(location, targets)| (module.offset(location), targets))
        .map(|(location, targets)| {
            let function = resolved_functions.get(&location).map(|v| *v);
            match function {
                Some(function) => Some((function, targets)),
                None => None,
            }
        });

    let mut function_calls: BTreeMap<u64, HashSet<u64>> = BTreeMap::new();
    for module_function in module_functions {
        if module_function.is_none() {
            bail!("no location match");
        }
        let (location, targets) = module_function.unwrap();

        let function_targets = function_calls.entry(location).or_default();
        function_targets.extend(targets);
    }

    // TODO: remove once proper impl is done
    let external_module = ModuleMetadata {
        name: "external".into(),
        base: 0,
        size: 0,
        path: "".into(),
    };

    let function_calls: BTreeMap<u64, Vec<Target>> = function_calls
        .into_iter()
        .map(|(function, targets)| {
            let targets: Vec<_> = targets
                .into_iter()
                .map(|target| {
                    if module.in_range(target) {
                        let offset = module.offset(target);
                        Target::new(&module, offset)
                    } else {
                        Target::new(&external_module, target)
                    }
                })
                .collect();
            (function, targets)
        })
        .collect();

    let external_calls = function_calls.iter().filter(|(_, targets)| {
        targets
            .iter()
            .filter(|target| target.module == &external_module)
            .count()
            > 0
    });
    for external_call in external_calls {
        dbg!(&external_call);
    }
    // dbg!(&function_calls);

    // let functions = module_functions.map(|(location, targets)| {
    //     let function = resolved_functions[location]
    // });

    // dbg!(&module_functions);

    // let offsets: Vec<_> = module_functions
    //     .map(|(location, _)| module.offset(*location))
    //     .sorted()
    //     .map(|offset| format!("{offset:#x}"))
    //     .collect();

    // let json = serde_json::to_string(&offsets)?;
    // println!("{json}");
    Ok(())
}
