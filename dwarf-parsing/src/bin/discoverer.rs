use std::fs::read_to_string;

use dwarf_parsing::discoverer::DiscovererJson;
use itertools::Itertools;

fn main() -> anyhow::Result<()> {
    let path = "../data/discoverer4.json";
    let binary_module = "godot.linuxbsd.editor.x86_64";

    let text = read_to_string(path)?;
    let json: DiscovererJson = serde_json::from_str(&text)?;

    let module = json
        .modules
        .iter()
        .find(|module| module.name == binary_module)
        .unwrap();

    let module_functions = json
        .functions
        .iter()
        .filter(|&(location, _)| module.in_range(*location));

    let offsets: Vec<_> = module_functions
        .map(|(location, _)| module.offset(*location))
        .sorted()
        .map(|offset| format!("{offset:#x}"))
        .collect();

    let json = serde_json::to_string(&offsets)?;
    println!("{json}");
    Ok(())
}
