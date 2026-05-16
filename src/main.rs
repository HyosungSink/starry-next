#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;
extern crate alloc;
extern crate axstd;

mod ctypes;
mod diag;

mod mm;
mod syscall_imp;
mod task;
use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use axhal::arch::UspaceContext;
use axstd::println;
use axsync::Mutex;
use memory_addr::VirtAddr;

struct TestCase {
    name: String,
    cwd: String,
    args: Vec<String>,
    direct_group: Option<String>,
}

fn parse_testcase(line: &str) -> Option<TestCase> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    if let Some((libc, group)) = line.split_once('/') {
        if matches!(libc, "musl" | "glibc") && !group.contains('/') {
            return Some(TestCase {
                name: line.to_string(),
                cwd: alloc::format!("/{libc}"),
                args: vec![
                    alloc::format!("/{libc}/busybox"),
                    "sh".to_string(),
                    alloc::format!("./{group}_testcode.sh"),
                ],
                direct_group: None,
            });
        }
    }

    Some(TestCase {
        name: line.to_string(),
        cwd: "/".to_string(),
        args: vec![line.to_string()],
        direct_group: Some("basic-musl".to_string()),
    })
}

fn run_user_app(testcase: TestCase) {
    println!("Testing {}: ", testcase.name);

    let old_cwd = axfs::api::current_dir().unwrap_or_else(|_| "/".to_string());
    if let Err(err) = axfs::api::set_current_dir(&testcase.cwd) {
        println!("testcase {} fail: set cwd {}: {:?}", testcase.name, testcase.cwd, err);
        return;
    }

    if let Some(group) = &testcase.direct_group {
        println!("#### OS COMP TEST GROUP START {} ####", group);
    }

    let mut args: VecDeque<String> = testcase.args.into();
    let mut uspace = axmm::new_user_aspace(
        VirtAddr::from_usize(axconfig::plat::USER_SPACE_BASE),
        axconfig::plat::USER_SPACE_SIZE,
    )
    .expect("Failed to create user address space");

    match mm::load_user_app(&mut args, &mut uspace) {
        Ok((entry_vaddr, ustack_top)) => {
            let user_task = task::spawn_user_task(
                Arc::new(Mutex::new(uspace)),
                UspaceContext::new(entry_vaddr.into(), ustack_top, 2333),
                0,
            );
            let _ = axfs::api::set_current_dir(&old_cwd);
            let exit_code = user_task.join();
            info!("User task {} exited with code: {:?}", testcase.name, exit_code);
        }
        Err(err) => {
            let _ = axfs::api::set_current_dir(&old_cwd);
            println!("testcase {} fail: load error {:?}", testcase.name, err);
        }
    }

    if let Some(group) = &testcase.direct_group {
        println!("#### OS COMP TEST GROUP END {} ####", group);
    }
}

#[unsafe(no_mangle)]
fn main() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter_map(parse_testcase);

    for testcase in testcases {
        run_user_app(testcase);
    }
}
