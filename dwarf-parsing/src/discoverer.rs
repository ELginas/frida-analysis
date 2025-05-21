use std::{
    collections::{BTreeSet, HashMap},
    fs::read_to_string,
    path::Path,
};

use anyhow::Context;
use ouroboros::self_referencing;

use crate::{
    module_map::{ModuleAddress, ModuleMap, ModuleMemory},
    parsing::{DiscovererJson, hex_to_num},
};

#[self_referencing]
pub struct DiscovererData {
    pub module_map: ModuleMap,
    #[borrows(module_map)]
    #[covariant]
    pub functions: HashMap<ModuleAddress<'this>, Vec<ModuleAddress<'this>>>,
}

impl DiscovererData {
    pub fn group_locations(&self) -> HashMap<&ModuleMemory, BTreeSet<&u64>> {
        let mut groups: HashMap<_, BTreeSet<_>> = HashMap::new();
        for location in self.borrow_functions().keys() {
            let group = groups.entry(location.module()).or_default();
            group.insert(location.offset());
        }
        groups
    }

    pub fn apply_resolved_locations(self, resolved_locations: &HashMap<u64, u64>) {
        // let mut functions: HashMap<_, Vec<_>> = HashMap::new();
        // for (location, targets) in self.borrow_functions() {
        //     let location = match resolved_locations.get(location.offset()) {
        //         Some(&new_offset) => location.new_offset(new_offset),
        //         None => location.clone(),
        //     };
        //     let function = functions.entry(location).or_default();
        //     function.extend(targets.into_iter().map(|module_address| *module_address));
        //
        let new_me = Self::new(self.borrow_module_map().clone(), |module_map| {
            let mut functions: HashMap<_, Vec<_>> = HashMap::new();
            for (location, targets) in self.borrow_functions() {
                // TODO
            }
            functions
        });
    }
}

impl From<DiscovererJson> for DiscovererData {
    fn from(value: DiscovererJson) -> Self {
        let module_map = value.modules;
        Self::new(module_map, |module_map| {
            let functions: HashMap<ModuleAddress<'_>, Vec<ModuleAddress<'_>>> = value
                .functions
                .into_iter()
                .map(|(location, targets)| {
                    // TODO: use errors instead of panics
                    let location = module_map.get_module_address(location).unwrap();
                    let targets: Vec<_> = targets
                        .into_iter()
                        .map(|target| module_map.get_module_address(target).unwrap())
                        .collect();
                    (location, targets)
                })
                .collect();
            functions
        })
    }
}

pub fn read_discoverer_data<P: AsRef<Path>>(path: P) -> anyhow::Result<DiscovererData> {
    let text = read_to_string(path)?;
    let data: DiscovererJson = serde_json::from_str(&text)?;
    let data: DiscovererData = data.into();
    Ok(data)
}

pub fn group_offset_json(
    groups: &HashMap<&ModuleMemory, BTreeSet<&u64>>,
    module_name: &str,
) -> String {
    let offsets = groups
        .iter()
        .find(|(module, _)| module.name() == module_name)
        .map(|(_, targets)| targets)
        .unwrap();

    let offsets: Vec<_> = offsets
        .iter()
        .map(|offset| format!("{offset:#x}"))
        .collect();

    let str = serde_json::to_string(&offsets).unwrap();
    str
}

pub fn read_resolved_locations<P: AsRef<Path>>(path: P) -> anyhow::Result<HashMap<u64, u64>> {
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
