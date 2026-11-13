// build.rs

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_dir(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

fn apply_patch(patch_file: &Path, workspace: &Path) {
    if !patch_file.is_file() {
        panic!("required NetBSD source patch is missing: {}", patch_file.display());
    }

    let status = Command::new("patch")
        .args(["-p1", "-F", "0", "-f", "-i"])
        .arg(patch_file)
        .current_dir(workspace)
        .status()
        .unwrap_or_else(|error| panic!("failed to run patch for {}: {error}", patch_file.display()));
    if !status.success() {
        panic!("failed to apply NetBSD source patch {} (patch exited with {status})", patch_file.display());
    }
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("src");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=src/bpfjit");
    println!("cargo:rerun-if-changed=src/sljit");
    println!("cargo:rerun-if-changed=patches/netbsd-bpfjit.patch");
    println!("cargo:rerun-if-changed=patches/netbsd-sljit.patch");

    let workspace = out_dir.join("netbsd-src");
    if workspace.exists() {
        fs::remove_dir_all(&workspace)
            .unwrap_or_else(|error| panic!("failed to clean NetBSD source workspace {}: {error}", workspace.display()));
    }
    let copied_src = workspace.join("src");
    copy_dir(&src.join("bpfjit"), &copied_src.join("bpfjit"))
        .unwrap_or_else(|error| panic!("failed to copy src/bpfjit into build workspace: {}", error));
    copy_dir(&src.join("sljit"), &copied_src.join("sljit"))
        .unwrap_or_else(|error| panic!("failed to copy src/sljit into build workspace: {}", error));

    apply_patch(&manifest.join("patches/netbsd-bpfjit.patch"), &workspace);
    apply_patch(&manifest.join("patches/netbsd-sljit.patch"), &workspace);

    let mut cc = cc::Build::new();
    cc.warnings(false);

    cc.define("SLJIT_CONFIG_AUTO", "1");
    // Apple uses its MAP_JIT allocator; the protected allocator is enabled
    // on other supported targets.
    let target = env::var("TARGET").unwrap();
    if target.contains("apple-darwin") {
        cc.define("SLJIT_PROT_EXECUTABLE_ALLOCATOR", "0");
    } else {
        cc.define("SLJIT_PROT_EXECUTABLE_ALLOCATOR", "1");
    }
    if target.contains("gnu") {
        cc.define("_GNU_SOURCE", "1");
        cc.define("HAVE_MEMFD_CREATE", "1");
    }
    cc.define("SLJIT_ARGUMENT_CHECKS", "1");
    cc.define("SLJIT_DEBUG", "0");
    cc.define("SLJIT_VERBOSE", "0");

    cc.include(&copied_src.join("sljit"));
    cc.include(&copied_src.join("bpfjit"));

    cc.file(copied_src.join("sljit").join("sljitLir.c"));
    cc.file(copied_src.join("bpfjit").join("bpfjit.c"));

    cc.compile("bpfjit");
}
