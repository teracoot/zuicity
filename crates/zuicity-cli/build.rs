#![allow(missing_docs, clippy::print_stdout)]

use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=ZUICITY_VERSION");
    println!("cargo:rerun-if-env-changed=VERSION");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let build_version = env::var("ZUICITY_VERSION")
        .or_else(|_| env::var("VERSION"))
        .or_else(|_| env::var("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| "unknown".to_owned());
    emit_env("ZUICITY_BUILD_VERSION", &build_version);
    emit_env("ZUICITY_RUSTC_VERSION", &rustc_version());
    emit_env(
        "ZUICITY_TARGET_OS",
        &env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_owned()),
    );
    emit_env(
        "ZUICITY_TARGET_ARCH",
        &env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_owned()),
    );
}

fn rustc_version() -> String {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_owned())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "rustc unknown".to_owned())
}

fn emit_env(name: &str, value: &str) {
    println!("cargo:rustc-env={name}={}", sanitize_env_value(value));
}

fn sanitize_env_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' => ' ',
            other => other,
        })
        .collect::<String>()
        .trim()
        .to_owned()
}
