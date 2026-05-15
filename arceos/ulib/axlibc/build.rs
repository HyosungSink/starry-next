fn main() {
    use std::env;
    use std::path::PathBuf;

    fn gen_c_to_rust_bindings(in_file: &str, out_file: &str) {
        println!("cargo:rerun-if-changed={in_file}");

        let allow_types = ["tm", "jmp_buf"];
        let mut builder = bindgen::Builder::default()
            .header(in_file)
            .clang_arg("-I./include")
            .derive_default(true)
            .size_t_is_usize(false)
            .use_core();
        for ty in allow_types {
            builder = builder.allowlist_type(ty);
        }

        builder
            .generate()
            .expect("Unable to generate c->rust bindings")
            .write_to_file(out_file)
            .expect("Couldn't write bindings!");
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let ctypes_header = manifest_dir.join("ctypes.h");
    let ctypes_rust = out_dir.join("libctypes_gen.rs");

    gen_c_to_rust_bindings(
        ctypes_header
            .to_str()
            .expect("ctypes header path is not valid UTF-8"),
        ctypes_rust
            .to_str()
            .expect("ctypes rust path is not valid UTF-8"),
    );
}
