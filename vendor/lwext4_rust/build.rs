use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() {
    let c_path = PathBuf::from("c/lwext4")
        .canonicalize()
        .expect("cannot canonicalize path");

    let lwext4_make = Path::new("c/lwext4/toolchain/musl-generic.cmake");
    let lwext4_patch = Path::new("c/lwext4-make.patch").canonicalize().unwrap();

    if !Path::new(lwext4_make).exists() {
        println!("Retrieve lwext4 source code");
        let git_status = Command::new("git")
            .args(&["submodule", "update", "--init", "--recursive"])
            .status()
            .expect("failed to execute process: git submodule");
        assert!(git_status.success());

        println!("To patch lwext4 src");
        Command::new("git")
            .args(&["apply", lwext4_patch.to_str().unwrap()])
            .current_dir(c_path.clone())
            .spawn()
            .expect("failed to execute process: git apply patch");

        fs::copy(
            "c/musl-generic.cmake",
            "c/lwext4/toolchain/musl-generic.cmake",
        )
        .unwrap();
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let lwext4_lib = &format!("lwext4-{}", arch);
    let lwext4_lib_path = &format!("c/lwext4/lib{}.a", lwext4_lib);
    let missing_lib = !Path::new(lwext4_lib_path).exists();
    let status = Command::new("make")
        .args(&[
            "musl-generic",
            "-C",
            c_path.to_str().expect("invalid path of lwext4"),
        ])
        .arg(&format!("ARCH={}", arch))
        .status()
        .expect("failed to execute process: make lwext4");
    assert!(status.success());

    if missing_lib {
        let cc = &format!("{}-linux-musl-gcc", arch);
        let output = Command::new(cc)
            .args(["-print-sysroot"])
            .output()
            .expect("failed to execute process: gcc -print-sysroot");

        let sysroot = core::str::from_utf8(&output.stdout).unwrap();
        let sysroot = sysroot.trim_end();
        let sysroot_inc = &format!("-I{}/include/", sysroot);
        generates_bindings_to_rust(sysroot_inc);
    }

    /* No longer need to implement the libc.a
    let libc_name = &format!("c-{}", arch);
    let libc_dir = env::var("LIBC_BUILD_TARGET_DIR").unwrap_or(String::from("./"));
    let libc_dir = PathBuf::from(libc_dir)
        .canonicalize()
        .expect("cannot canonicalize LIBC_BUILD_TARGET_DIR");

    println!("cargo:rustc-link-lib=static={libc_name}");
    println!(
        "cargo:rustc-link-search=native={}",
        libc_dir.to_str().unwrap()
    );
    */

    println!("cargo:rustc-link-lib=static={lwext4_lib}");
    println!(
        "cargo:rustc-link-search=native={}",
        c_path.to_str().unwrap()
    );
    println!("cargo:rerun-if-changed=c/wrapper.h");
    println!("cargo:rerun-if-changed={}", c_path.to_str().unwrap());
}

#[cfg(target_arch = "x86_64")]
fn generates_bindings_to_rust(_mpath: &str) {}

#[cfg(not(target_arch = "x86_64"))]
fn generates_bindings_to_rust(_mpath: &str) {
    assert!(
        Path::new("src/bindings.rs").exists(),
        "missing vendored bindings.rs for lwext4_rust"
    );
}
