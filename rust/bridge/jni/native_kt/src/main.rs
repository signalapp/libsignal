//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
// To make sure the linkmes work
extern crate libsignal_bridge;
extern crate libsignal_bridge_testing;
extern crate libsignal_jni_impl;

use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use clap::Parser;
use heck::ToLowerCamelCase;
use libsignal_bridge_types::jni::{JNI_ITEMS, KtMetadataContext};
use minijinja::context;

#[derive(Parser)]
/// Regenerate NativeNice.kt and NativeNiceTesting.kt
///
/// This command assumes it's being invoked from the workspace root.
struct Cli {
    /// Don't actually overwrite output files, just make sure they're up-to-date.
    #[clap(long)]
    verify: bool,
}

struct RemoveOnDrop {
    path: PathBuf,
}
impl std::ops::Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn preserve_underscores(
    inner: impl Fn(&str) -> String + 'static,
) -> impl Fn(String) -> String + 'static {
    move |x| {
        let x_sans_underscore = x.trim_start_matches('_');
        let core = inner(x_sans_underscore);
        format!("{}{core}", &x[0..(x.len() - x_sans_underscore.len())])
    }
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_filter(
        "to_lower_camel_case",
        preserve_underscores(ToLowerCamelCase::to_lower_camel_case),
    );
    env.add_template("NativeNice.kt.in", include_str!("NativeNice.kt.in"))?;
    let mut non_testing_ctx = KtMetadataContext::default();
    let mut testing_ctx = KtMetadataContext::default();
    for item in JNI_ITEMS.iter() {
        (item.apply)(
            if item.module_path.starts_with("libsignal_bridge_testing") {
                &mut testing_ctx
            } else {
                &mut non_testing_ctx
            },
        );
    }
    for testing in [false, true] {
        let code = env.get_template("NativeNice.kt.in")?.render(context! {
            non_testing_ctx => non_testing_ctx,
            testing_ctx => testing_ctx,
            testing => testing,
        })?;
        let dst = PathBuf::from(if testing {
            "./java/client/src/test/java/org/signal/libsignal/internal/NativeTestingNice.kt"
        } else {
            "./java/client/src/main/java/org/signal/libsignal/internal/NativeNice.kt"
        });
        let base_dir = dst.parent().expect("dst is not root");
        let tmp = RemoveOnDrop {
            path: std::path::absolute(base_dir.join("NiceTmp.kt"))?,
        };
        std::fs::write(&tmp.path, code.as_bytes())?;
        let status = Command::new("./gradlew")
            .current_dir("./java")
            .arg(format!(
                "-PspotlessIdeHook={}",
                tmp.path.to_str().context("path should be utf-8")?
            ))
            .args([
                "--dependency-verification",
                "strict",
                "-PskipAndroid",
                "spotlessApply",
            ])
            .status()?;
        anyhow::ensure!(status.success(), "kotlin formatting failed");
        let code = std::fs::read_to_string(&tmp.path)?;
        if args.verify {
            anyhow::ensure!(
                std::fs::read_to_string(&dst)? == code,
                "{dst:?} is not up-to-date"
            );
        } else {
            std::fs::write(&dst, code.as_bytes())?;
        }
    }
    Ok(())
}
