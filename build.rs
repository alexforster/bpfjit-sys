// build.rs

use std::env;
use std::path::PathBuf;

fn main() {
    let src = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("src");

    let mut cc = cc::Build::new();
    cc.warnings(false);

    cc.define("SLJIT_CONFIG_AUTO", "1");
    if env::var("TARGET").unwrap().contains("apple-darwin") {
        cc.define("SLJIT_PROT_EXECUTABLE_ALLOCATOR", "0");
    } else {
        cc.define("SLJIT_PROT_EXECUTABLE_ALLOCATOR", "1");
    }
    cc.define("SLJIT_ARGUMENT_CHECKS", "1");
    cc.define("SLJIT_DEBUG", "0");
    cc.define("SLJIT_VERBOSE", "0");
    cc.define("__BPF_PRIVATE", "1");

    cc.include(&src.join("sljit"));
    cc.include(&src.join("bpfjit"));

    cc.file(src.join("sljit").join("sljitLir.c"));
    cc.file(src.join("bpfjit").join("bpfjit.c"));

    cc.compile("bpfjit");
}
