use dwarf_parsing::dwarf;

fn main() {
    // let path = "/home/user/projects/frida-examples/src/a.out";
    let path = "/home/user/GithubRepos/godot/bin/godot.linuxbsd.editor.x86_64.debugsymbols";
    dwarf::run(path);
}
