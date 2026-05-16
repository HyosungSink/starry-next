#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "contest_diag_logs")]
        {
            warn!($($arg)*);
        }
    }};
}

use alloc::{format, string::String, vec::Vec};
use axstd::println;

const SNAPSHOT_ROOTS: &[&str] = &[
    "/",
    "/musl",
    "/glibc",
    "/basic",
    "/musl/basic",
    "/glibc/basic",
    "/bin",
    "/musl/lib",
    "/glibc/lib",
];
const SNAPSHOT_MAX_DEPTH: usize = 2;
const SNAPSHOT_MAX_ENTRIES: usize = 48;

fn print_dir_tree(path: &str, depth: usize) {
    let indent = format!("{:width$}", "", width = depth * 2);
    match axfs::api::read_dir(path) {
        Ok(entries) => {
            let mut children: Vec<(String, bool)> = Vec::new();
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                children.push((entry.path(), entry.file_type().is_dir()));
            }
            children.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

            println!("{}{}", indent, path);
            let child_indent = format!("{:width$}", "", width = (depth + 1) * 2);
            for (index, (child, is_dir)) in children.iter().enumerate() {
                if index >= SNAPSHOT_MAX_ENTRIES {
                    println!(
                        "{}... {} more entries omitted",
                        child_indent,
                        children.len() - SNAPSHOT_MAX_ENTRIES
                    );
                    break;
                }
                let name = child.rsplit('/').next().unwrap_or(child.as_str());
                println!(
                    "{}- {}{}",
                    child_indent,
                    name,
                    if *is_dir { "/" } else { "" }
                );
                if *is_dir && depth < SNAPSHOT_MAX_DEPTH {
                    print_dir_tree(child.as_str(), depth + 2);
                }
            }
        }
        Err(err) => println!("{}{} <read_dir failed: {:?}>", indent, path, err),
    }
}

pub(crate) fn print_competition_layout_snapshot() {
    println!("#### OS COMP FS SNAPSHOT START ####");
    println!("cwd = {:?}", axfs::api::current_dir().ok());
    for root in SNAPSHOT_ROOTS {
        print_dir_tree(root, 0);
    }
    println!("#### OS COMP FS SNAPSHOT END ####");
}
