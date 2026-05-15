use std::env;
use std::fs::{File, copy, create_dir_all, read_dir, symlink_metadata};
use std::io::{Error, ErrorKind, Result, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct StagedEmbeddedFileEntry {
    path: String,
    expr: String,
    refresh_if_exists: bool,
    executable: bool,
}

fn main() {
    println!("cargo:rerun-if-changed=./apps/c/src");
    println!("cargo:rerun-if-changed=./apps/rust/src");
    println!("cargo:rerun-if-changed=.makeargs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=embedded-runtime-refresh");
    println!("cargo:rerun-if-env-changed=PATH");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    link_app_data(&arch).unwrap();
    generate_embedded_runtime(&arch).unwrap();
}

fn link_app_data(arch: &str) -> Result<()> {
    let testcase = option_env!("AX_TESTCASE").unwrap_or("nimbos");

    let app_path = PathBuf::from(format!("apps/{}/build/{}", testcase, arch));
    let link_app_path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("link_app.S");

    if let Ok(dir) = read_dir(&app_path) {
        let mut apps = dir
            .into_iter()
            .map(|dir_entry| dir_entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        apps.sort();

        let mut f = File::create(link_app_path)?;
        writeln!(
            f,
            "
.section .data
.balign 8
.global _app_count
_app_count:
    .quad {}",
            apps.len()
        )?;
        for i in 0..apps.len() {
            writeln!(f, "    .quad app_{}_name", i)?;
            writeln!(f, "    .quad app_{}_start", i)?;
        }
        writeln!(f, "    .quad app_{}_end", apps.len() - 1)?;

        for (idx, app) in apps.iter().enumerate() {
            println!("app_{}: {}", idx, app_path.join(app).display());
            writeln!(
                f,
                "
app_{0}_name:
    .string \"{1}\"
.balign 8
app_{0}_start:
    .incbin \"{2}\"
app_{0}_end:",
                idx,
                app,
                app_path.join(app).display()
            )?;
        }
    } else {
        let mut f = File::create(link_app_path)?;
        writeln!(
            f,
            "
.section .data
.balign 8
.global _app_count
_app_count:
    .quad 0"
        )?;
    }
    Ok(())
}

fn generate_embedded_runtime(target_arch: &str) -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let staged_dir = out_dir.join("embedded-runtime");
    create_dir_all(&staged_dir)?;

    let rv_loader = locate_riscv_musl_loader();
    let rv_libc = locate_riscv_musl_libc();
    let rv_glibc_loader =
        optional_vendored_refresh_runtime_file("rv", "glibc", "lib/ld-linux-riscv64-lp64d.so.1");
    let rv_glibc_libc = optional_vendored_refresh_runtime_file("rv", "glibc", "lib/libc.so.6");
    let la_loader = locate_loongarch_musl_loader();
    let la_libc = locate_loongarch_musl_libc();

    if target_arch == "riscv64" {
        require_runtime("riscv64", "ld-musl-riscv64.so.1", rv_loader.as_ref())?;
        require_runtime("riscv64", "libc.so", rv_libc.as_ref())?;
    }
    if target_arch == "loongarch64" {
        require_runtime(
            "loongarch64",
            "ld-musl-loongarch64.so.1",
            la_loader.as_ref(),
        )?;
        require_runtime("loongarch64", "libc.so", la_libc.as_ref())?;
    }

    let rv_loader_expr =
        stage_runtime_expr(&staged_dir, "rv-ld-musl-riscv64.so.1", rv_loader.as_ref())?;
    let rv_libc_expr = stage_runtime_expr(&staged_dir, "rv-libc.so", rv_libc.as_ref())?;
    let rv_glibc_loader_expr = stage_optional_existing_file_expr(
        &staged_dir,
        "rv-ld-linux-riscv64-lp64d.so.1",
        rv_glibc_loader.as_ref(),
    )?;
    let rv_glibc_libc_expr = stage_optional_existing_file_expr(
        &staged_dir,
        "rv-glibc-libc.so.6",
        rv_glibc_libc.as_ref(),
    )?;
    let la_loader_expr = stage_runtime_expr(
        &staged_dir,
        "la-ld-musl-loongarch64.so.1",
        la_loader.as_ref(),
    )?;
    let la_libc_expr = stage_runtime_expr(&staged_dir, "la-libc.so", la_libc.as_ref())?;
    let glibc_locale_entries = stage_embedded_file_entries(
        &staged_dir,
        "glibc-locale",
        collect_glibc_locale_files()?,
        false,
    )?;
    let rv_refresh_entries = if target_arch == "riscv64" {
        stage_embedded_file_entries(
            &staged_dir,
            "rv-online-refresh",
            collect_online_refresh_runtime_files("rv")?,
            true,
        )?
    } else {
        Vec::new()
    };
    let la_refresh_entries = if target_arch == "loongarch64" {
        stage_embedded_file_entries(
            &staged_dir,
            "la-online-refresh",
            collect_online_refresh_runtime_files("la")?,
            true,
        )?
    } else {
        Vec::new()
    };

    let mut out = File::create(out_dir.join("embedded_runtime.rs"))?;
    writeln!(
        out,
        "pub(crate) struct EmbeddedRuntimeFile {{ pub path: &'static str, pub data: &'static [u8], pub refresh_if_exists: bool, pub executable: bool }}"
    )?;
    writeln!(
        out,
        "pub(crate) const RV_MUSL_LOADER: &[u8] = {rv_loader_expr};"
    )?;
    writeln!(
        out,
        "pub(crate) const RV_MUSL_LIBC: &[u8] = {rv_libc_expr};"
    )?;
    writeln!(
        out,
        "pub(crate) const RV_GLIBC_LOADER: &[u8] = {rv_glibc_loader_expr};"
    )?;
    writeln!(
        out,
        "pub(crate) const RV_GLIBC_LIBC: &[u8] = {rv_glibc_libc_expr};"
    )?;
    writeln!(
        out,
        "pub(crate) const LA_MUSL_LOADER: &[u8] = {la_loader_expr};"
    )?;
    writeln!(
        out,
        "pub(crate) const LA_MUSL_LIBC: &[u8] = {la_libc_expr};"
    )?;
    writeln!(
        out,
        "#[cfg(target_arch = \"riscv64\")]\npub(crate) const MUSL_INTERP_BYTES: &[u8] = RV_MUSL_LOADER;"
    )?;
    writeln!(
        out,
        "#[cfg(target_arch = \"loongarch64\")]\npub(crate) const MUSL_INTERP_BYTES: &[u8] = LA_MUSL_LOADER;"
    )?;
    writeln!(
        out,
        "#[cfg(target_arch = \"riscv64\")]\npub(crate) const EMBEDDED_RUNTIME_FILES: &[EmbeddedRuntimeFile] = &["
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib/ld-musl-riscv64.so.1",
        "RV_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib/ld-musl-riscv64-sf.so.1",
        "RV_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/musl/lib/ld-musl-riscv64.so.1",
        "RV_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/musl/lib/ld-musl-riscv64-sf.so.1",
        "RV_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(&mut out, "/lib/libc.so", "RV_MUSL_LIBC", false, false)?;
    write_embedded_runtime_entry(&mut out, "/lib64/libc.so", "RV_MUSL_LIBC", false, false)?;
    write_embedded_runtime_entry(&mut out, "/musl/lib/libc.so", "RV_MUSL_LIBC", false, false)?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib/ld-linux-riscv64-lp64d.so.1",
        "RV_GLIBC_LOADER",
        true,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib/libc.so.6",
        "RV_GLIBC_LIBC",
        true,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib64/libc.so.6",
        "RV_GLIBC_LIBC",
        true,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/glibc/lib/ld-linux-riscv64-lp64d.so.1",
        "RV_GLIBC_LOADER",
        true,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/glibc/lib/libc.so.6",
        "RV_GLIBC_LIBC",
        true,
        false,
    )?;
    for entry in &glibc_locale_entries {
        write_embedded_runtime_entry(
            &mut out,
            entry.path.as_str(),
            entry.expr.as_str(),
            entry.refresh_if_exists,
            entry.executable,
        )?;
    }
    for entry in &rv_refresh_entries {
        write_embedded_runtime_entry(
            &mut out,
            entry.path.as_str(),
            entry.expr.as_str(),
            entry.refresh_if_exists,
            entry.executable,
        )?;
    }
    writeln!(out, "];")?;
    writeln!(
        out,
        "#[cfg(target_arch = \"loongarch64\")]\npub(crate) const EMBEDDED_RUNTIME_FILES: &[EmbeddedRuntimeFile] = &["
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib/ld-musl-loongarch64.so.1",
        "LA_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/lib64/ld-musl-loongarch-lp64d.so.1",
        "LA_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/musl/lib/ld-musl-loongarch64.so.1",
        "LA_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(
        &mut out,
        "/musl/lib64/ld-musl-loongarch-lp64d.so.1",
        "LA_MUSL_LOADER",
        false,
        false,
    )?;
    write_embedded_runtime_entry(&mut out, "/lib/libc.so", "LA_MUSL_LIBC", false, false)?;
    write_embedded_runtime_entry(&mut out, "/lib64/libc.so", "LA_MUSL_LIBC", false, false)?;
    write_embedded_runtime_entry(&mut out, "/musl/lib/libc.so", "LA_MUSL_LIBC", false, false)?;
    for entry in &glibc_locale_entries {
        write_embedded_runtime_entry(
            &mut out,
            entry.path.as_str(),
            entry.expr.as_str(),
            entry.refresh_if_exists,
            entry.executable,
        )?;
    }
    for entry in &la_refresh_entries {
        write_embedded_runtime_entry(
            &mut out,
            entry.path.as_str(),
            entry.expr.as_str(),
            entry.refresh_if_exists,
            entry.executable,
        )?;
    }
    writeln!(out, "];")?;
    Ok(())
}

fn write_embedded_runtime_entry(
    out: &mut File,
    path: &str,
    expr: &str,
    refresh_if_exists: bool,
    executable: bool,
) -> Result<()> {
    writeln!(
        out,
        "    EmbeddedRuntimeFile {{ path: {:?}, data: {}, refresh_if_exists: {}, executable: {} }},",
        path, expr, refresh_if_exists, executable
    )
}

fn require_runtime(arch: &str, name: &str, path: Option<&PathBuf>) -> Result<()> {
    if path.is_some() {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::NotFound,
        format!("missing embedded musl runtime for {arch}: {name}"),
    ))
}

fn stage_runtime_expr(
    staged_dir: &Path,
    staged_name: &str,
    src: Option<&PathBuf>,
) -> Result<String> {
    let Some(src) = src else {
        return Ok("&[]".to_string());
    };
    let staged_path = staged_dir.join(staged_name);
    copy(src, &staged_path)?;
    println!("cargo:rerun-if-changed={}", src.display());
    Ok(format!(
        "include_bytes!({:?}) as &[u8]",
        staged_path.to_string_lossy()
    ))
}

fn stage_existing_file_expr(staged_dir: &Path, staged_name: &str, src: &Path) -> Result<String> {
    let staged_path = staged_dir.join(staged_name);
    copy(src, &staged_path)?;
    println!("cargo:rerun-if-changed={}", src.display());
    Ok(format!(
        "include_bytes!({:?}) as &[u8]",
        staged_path.to_string_lossy()
    ))
}

fn stage_optional_existing_file_expr(
    staged_dir: &Path,
    staged_name: &str,
    src: Option<&PathBuf>,
) -> Result<String> {
    let Some(src) = src else {
        return Ok("&[]".to_string());
    };
    stage_existing_file_expr(staged_dir, staged_name, src)
}

fn stage_embedded_file_entries(
    staged_dir: &Path,
    staged_prefix: &str,
    files: Vec<(String, PathBuf)>,
    refresh_if_exists: bool,
) -> Result<Vec<StagedEmbeddedFileEntry>> {
    let mut entries = Vec::new();
    for (index, (path, src)) in files.into_iter().enumerate() {
        let stem = src
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file");
        let staged_name = format!("{staged_prefix}-{index:04}-{stem}");
        let expr = stage_existing_file_expr(staged_dir, &staged_name, &src)?;
        entries.push(StagedEmbeddedFileEntry {
            path,
            expr,
            refresh_if_exists,
            executable: is_executable_file(&src)?,
        });
    }
    Ok(entries)
}

fn collect_glibc_locale_files() -> Result<Vec<(String, PathBuf)>> {
    let base_dir = Path::new("/usr/lib/locale/C.utf8");
    let mut files = Vec::new();
    if base_dir.exists() {
        collect_files_recursive(base_dir, base_dir, &mut files)?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
    }
    let mut entries = files
        .into_iter()
        .map(|(relative, src)| (format!("/usr/lib/locale/C.utf8/{relative}"), src))
        .collect::<Vec<_>>();

    let locale_archive = PathBuf::from("/usr/lib/locale/locale-archive");
    if locale_archive.exists() {
        entries.push(("/usr/lib/locale/locale-archive".to_string(), locale_archive));
    }
    Ok(entries)
}

fn collect_online_refresh_runtime_files(arch_dir: &str) -> Result<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for runtime in ["glibc", "musl"] {
        let Some(runtime_root) = locate_online_refresh_runtime_dir(arch_dir, runtime) else {
            println!(
                "cargo:warning=skip embedded online refresh for arch={} runtime={} because no runtime root was found",
                arch_dir, runtime
            );
            continue;
        };
        let basic_dir = runtime_root.join("basic");
        if !basic_dir.is_dir() {
            println!(
                "cargo:warning=skip embedded online refresh for arch={} runtime={} because basic dir is missing at {}",
                arch_dir,
                runtime,
                basic_dir.display()
            );
            continue;
        }
        let mut basic_entries = Vec::new();
        collect_files_recursive(&runtime_root, &basic_dir, &mut basic_entries)?;
        for (relative, src) in basic_entries {
            entries.push((format!("/{runtime}/{relative}"), src));
        }
        for rel in [
            ".basic_testcode.sh.raw",
            "basic_testcode.sh",
            "busybox",
            "busybox_cmd.txt",
            ".busybox_testcode.sh.raw",
            "busybox_testcode.sh",
            ".libctest_testcode.sh.raw",
            "libctest_testcode.sh",
            "entry-static.exe",
            "entry-dynamic.exe",
            ".cyclictest_testcode.sh.raw",
            "cyclictest_testcode.sh",
            "cyclictest",
            "hackbench",
        ] {
            if let Err(err) = push_refresh_runtime_file(&mut entries, runtime, &runtime_root, rel) {
                println!(
                    "cargo:warning=skip embedded online refresh file for arch={} runtime={} relative={} err={}",
                    arch_dir, runtime, rel, err
                );
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn locate_online_refresh_runtime_dir(arch_dir: &str, runtime: &str) -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    for base in manifest_dir.ancestors() {
        let vendored = base
            .join("kernel/starry-next/embedded-runtime-refresh")
            .join(arch_dir)
            .join(runtime);
        if vendored.join("basic").is_dir() {
            return Some(vendored);
        }
    }
    None
}

fn optional_vendored_refresh_runtime_file(
    arch_dir: &str,
    runtime: &str,
    relative: &str,
) -> Option<PathBuf> {
    let Some(runtime_root) = locate_online_refresh_runtime_dir(arch_dir, runtime) else {
        println!(
            "cargo:warning=missing vendored embedded online refresh runtime root for arch={} runtime={}, keep compiling without {}",
            arch_dir, runtime, relative
        );
        return None;
    };
    match resolve_refresh_runtime_file(&runtime_root, relative) {
        Ok(path) => Some(path),
        Err(err) => {
            println!(
                "cargo:warning=missing vendored embedded online refresh file for arch={} runtime={} relative={} err={}",
                arch_dir, runtime, relative, err
            );
            None
        }
    }
}

fn push_refresh_runtime_file(
    out: &mut Vec<(String, PathBuf)>,
    runtime: &str,
    runtime_root: &Path,
    relative: &str,
) -> Result<()> {
    let path = resolve_refresh_runtime_file(runtime_root, relative)?;
    let metadata = symlink_metadata(&path)?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "embedded online refresh path is not a file: {}",
                path.display()
            ),
        ));
    }
    out.push((format!("/{runtime}/{relative}"), path));
    Ok(())
}

fn resolve_refresh_runtime_file(runtime_root: &Path, relative: &str) -> Result<PathBuf> {
    let direct = runtime_root.join(relative);
    if direct.is_file() {
        return Ok(direct);
    }

    Err(Error::new(
        ErrorKind::NotFound,
        format!(
            "missing vendored embedded online refresh file {}",
            direct.display()
        ),
    ))
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_files_recursive(root, &path, out)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
        out.push((relative.to_string_lossy().replace('\\', "/"), path));
    }
    Ok(())
}

fn is_executable_file(path: &Path) -> Result<bool> {
    let metadata = symlink_metadata(path)?;
    #[cfg(unix)]
    {
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(false)
    }
}

fn locate_riscv_musl_loader() -> Option<PathBuf> {
    find_runtime_file(
        &["riscv64-linux-musl-gcc", "riscv64-buildroot-linux-musl-gcc"],
        "ld-musl-riscv64.so.1",
        &vec![
            PathBuf::from(
                "/opt/riscv64-linux-musl-cross/riscv64-linux-musl/lib/ld-musl-riscv64.so.1",
            ),
            PathBuf::from(
                "/opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/riscv64-buildroot-linux-musl/sysroot/lib/ld-musl-riscv64.so.1",
            ),
        ],
    )
}

fn locate_riscv_musl_libc() -> Option<PathBuf> {
    find_runtime_file(
        &["riscv64-linux-musl-gcc", "riscv64-buildroot-linux-musl-gcc"],
        "libc.so",
        &vec![
            PathBuf::from("/opt/riscv64-linux-musl-cross/riscv64-linux-musl/lib/libc.so"),
            PathBuf::from(
                "/opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/riscv64-buildroot-linux-musl/sysroot/lib/libc.so",
            ),
        ],
    )
}

fn locate_loongarch_musl_loader() -> Option<PathBuf> {
    let repo_root = repo_root();
    find_runtime_file(
        &["loongarch64-linux-musl-gcc"],
        "ld-musl-loongarch64.so.1",
        &vec![
            repo_root.join("testsuits-for-oskernel-pre-2025/runtime/loongarch/lib64/ld.so"),
            PathBuf::from(
                "/opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/lib/ld-musl-loongarch64.so.1",
            ),
        ],
    )
}

fn locate_loongarch_musl_libc() -> Option<PathBuf> {
    let repo_root = repo_root();
    find_runtime_file(&["loongarch64-linux-musl-gcc"], "libc.so", &vec![
        repo_root.join("testsuits-for-oskernel-pre-2025/runtime/loongarch/lib64/libc.so"),
        PathBuf::from("/opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/lib/libc.so"),
    ])
}

fn find_runtime_file(
    compilers: &[&str],
    file_name: &str,
    fallback_paths: &[PathBuf],
) -> Option<PathBuf> {
    for compiler in compilers {
        for base in compiler_search_dirs(compiler) {
            let candidate = base.join(file_name);
            if let Some(path) = resolve_runtime_source(&candidate, file_name) {
                return Some(path);
            }
        }
    }
    fallback_paths
        .iter()
        .find_map(|path| resolve_runtime_source(path, file_name))
}

fn resolve_runtime_source(candidate: &Path, file_name: &str) -> Option<PathBuf> {
    if candidate.exists() {
        return Some(candidate.to_path_buf());
    }

    let metadata = symlink_metadata(candidate).ok()?;
    if !metadata.file_type().is_symlink() {
        return None;
    }

    let parent = candidate.parent()?;
    let link_target = candidate.read_link().ok()?;
    let mut possible_sources = Vec::new();
    if link_target.is_relative() {
        possible_sources.push(parent.join(&link_target));
    }
    if let Some(name) = link_target.file_name() {
        possible_sources.push(parent.join(name));
    }
    if file_name.starts_with("ld-musl-") {
        possible_sources.push(parent.join("libc.so"));
    }

    for source in possible_sources {
        if source.exists() {
            println!(
                "cargo:warning=resolved musl runtime {} via {}",
                candidate.display(),
                source.display()
            );
            return Some(source);
        }
    }

    None
}

fn compiler_search_dirs(compiler: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Some(sysroot) = compiler_sysroot(compiler) else {
        return dirs;
    };
    dirs.push(sysroot.join("lib"));
    dirs.push(sysroot.join("usr/lib"));
    dirs.push(sysroot.join("lib64"));
    dirs.push(sysroot.join("usr/lib64"));
    dirs
}

fn compiler_sysroot(compiler: &str) -> Option<PathBuf> {
    let output = Command::new(compiler).arg("-print-sysroot").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sysroot.is_empty() {
        return None;
    }
    let path = PathBuf::from(sysroot);
    path.exists().then_some(path)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}
