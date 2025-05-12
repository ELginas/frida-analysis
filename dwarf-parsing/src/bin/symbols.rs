use dwarf_parsing::symbols;

fn main() {
    let path = "/home/user/GithubRepos/godot/bin/godot.linuxbsd.editor.x86_64.debugsymbols";
    symbols::run(path);
}
