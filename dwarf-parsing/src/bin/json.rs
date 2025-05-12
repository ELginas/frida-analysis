use dwarf_parsing::json::{map_function_counts, read_json, read_symbols};

fn main() -> anyhow::Result<()> {
    let path = "../data/46654.json";
    let symbol_path = "/home/user/GithubRepos/godot/bin/godot.linuxbsd.editor.x86_64.debugsymbols";
    let module = "godot.linuxbsd.editor.x86_64";

    let function_counts = read_json(path, module)?;
    let symbols = read_symbols(symbol_path)?;
    let function_counts = map_function_counts(function_counts, &symbols);
    let json_str = serde_json::to_string(&function_counts).unwrap();
    println!("{json_str}");
    Ok(())
}
