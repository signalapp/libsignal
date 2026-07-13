//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// To make sure the linkmes work
extern crate libsignal_bridge;
extern crate libsignal_bridge_testing;
extern crate libsignal_ffi_impl;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use clap::Parser;
use heck::ToLowerCamelCase;
use itertools::Itertools;
use libsignal_bridge_types::ffi::{FFI_ITEMS, SwiftMetadataContext};
use libsignal_bridge_types::metadata::ffi::capi::{
    CFunctionPrototype, CType, RustType, UtilityTypedef,
};
use libsignal_bridge_types::metadata::{preserve_underscores, remove_all_checked};
use minijinja::context;
use minijinja::value::DynObject;

#[derive(Parser)]
/// Regenerate NativeNice.swift and NativeNiceTesting.swift
///
/// This command assumes it's being invoked from the workspace root.
struct Cli {
    /// Don't actually overwrite output files, just make sure they're up-to-date.
    #[clap(long)]
    verify: bool,
    /// Just dump all metadata to JSON on stdout; do nothing else.
    #[clap(long)]
    dump_json: bool,
}

fn to_snake_case(x: String) -> String {
    match x.as_str() {
        "double" | "Double" => "double_".to_string(),
        _ => preserve_underscores(heck::ToSnakeCase::to_snake_case)(x),
    }
}

fn emit_utility_typedefs(
    env: &minijinja::Environment,
    code: &mut String,
    visited: &mut BTreeSet<RustType>,
    c_types: &BTreeMap<RustType, Arc<CType>>,
    rust_type: RustType,
) {
    if visited.contains(&rust_type) {
        return;
    }
    let cty = c_types
        .get(&rust_type)
        .unwrap_or_else(|| panic!("No ctype for {rust_type:?}"));
    for dep in cty.dependencies.iter().copied() {
        emit_utility_typedefs(env, code, visited, c_types, dep);
    }
    visited.insert(rust_type);
    let typedefs = match &cty.utility_typedefs {
        UtilityTypedef::String(out) => out.clone(),
        UtilityTypedef::StructTypedef { type_name, fields } => env
            .get_template("typedef_templates/struct.typedef.txt")
            .expect("found template")
            .render(context! {
                type_name,
                fields,
            })
            .expect("template rendered"),
        UtilityTypedef::EnumWithPayloads { type_name, ty } => env
            .get_template("typedef_templates/enum_with_payloads.typedef.txt")
            .expect("found template")
            .render(context! {
                type_name,
                variants => &ty.variants,
            })
            .expect("template rendered"),
        UtilityTypedef::EnumWithoutPayloads {
            type_name,
            variants,
            repr_ty,
        } => env
            .get_template("typedef_templates/enum_without_payloads.typedef.txt")
            .expect("found template")
            .render(context! {
                type_name,
                variants,
                repr_ty,
                print_values => !variants
                    .iter().enumerate().all(|(i, (_, value))| (i as i128) == *value),
            })
            .expect("template rendered"),
    };
    if !typedefs.is_empty() {
        writeln!(code, "{}", typedefs).expect("string write");
    }
    if let Some(layout) = cty.layout {
        writeln!(
            code,
            "static_assert_64bit(sizeof({}) == {});",
            cty.type_name,
            layout.size()
        )
        .expect("string write");
        writeln!(
            code,
            "static_assert_64bit(alignof({}) == {});",
            cty.type_name,
            layout.align()
        )
        .expect("string write");
    }
}
fn emit_c_function(code: &mut String, name: &str, func: &CFunctionPrototype) {
    if func.result.rust_type != RustType::of::<()>() {
        assert!(
            func.result.layout.is_some(),
            "Return type of {name:?} must not be opaque"
        );
    }
    for (arg, ty) in func.args.iter() {
        assert!(
            ty.layout.is_some(),
            "Arg {arg:?} of {name:?} must not be opaque"
        );
    }
    if func.args.is_empty() {
        writeln!(code, "{} {name}(void);", func.result.ptr_type_name()).expect("string write");
    } else {
        writeln!(
            code,
            "{} {name}({}\n);",
            func.result.ptr_type_name(),
            func.args
                .iter()
                .map(|(arg, ty)| format!("\n{} {arg}", ty.ptr_type_name()))
                .join(",")
        )
        .expect("string write");
    }
}

/// We don't want to depend on clang format, so here's a very simple pretty-printing solution.
fn prettify_c(code: &str) -> String {
    let mut indent = 0;
    code.split('\n')
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            if line.starts_with(")") || line.starts_with("}") {
                indent -= 1;
            }
            let mut out = String::with_capacity(line.len() + indent * 2);
            for _ in 0..indent {
                out.push_str("  ");
            }
            out.push_str(line);
            for (i, ch) in line.chars().enumerate() {
                match ch {
                    '(' | '{' => indent += 1,
                    ')' | '}' if i != 0 => indent -= 1,
                    _ => {}
                }
            }
            out
        })
        .join("\n")
}

const NON_TESTING_HEADER_H: &str = r#"
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
// AUTOGENERATED! Do not modify!

#pragma once

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A static assert that's only enabled for 64-bit platforms.
#define static_assert_64bit(flag) static_assert((sizeof(void*) == 8) ? (flag) : 1, "")
"#;

const TESTING_HEADER_H: &str = r#"
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
// AUTOGENERATED! Do not modify!

#pragma once

#include "signal_ffi.h"
"#;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_filter("to_snake_case", to_snake_case);
    env.add_filter(
        "to_lower_camel_case",
        preserve_underscores(ToLowerCamelCase::to_lower_camel_case),
    );
    env.add_filter("arg_converter", |ty: String| {
        libsignal_bridge_types::metadata::ffi::names::arg_converter(&ty)
    });
    env.add_filter("return_converter", |ty: String| {
        libsignal_bridge_types::metadata::ffi::names::return_converter(&ty)
    });
    env.add_filter("fixed_byte_array_helper", |len: usize| {
        libsignal_bridge_types::metadata::ffi::names::fixed_byte_array_helper(len)
    });
    env.add_function("enum_has_payload", |e: DynObject| {
        e.get_value_by_str("variants")
            .expect("missing variants")
            .try_iter()
            .expect("enumerate variants")
            .any(|name_struct_pair| {
                name_struct_pair
                    .get_item_by_index(1)
                    .expect("get_item_by_index()")
                    .as_object()
                    .expect("struct is object")
                    .get_value_by_str("fields")
                    .expect("missing fields")
                    .len()
                    .expect("fields has len")
                    > 0
            })
    });
    env.add_template("NativeNice.swift.in", include_str!("NativeNice.swift.in"))?;
    env.add_template(
        "typedef_templates/struct.typedef.txt",
        include_str!("typedef_templates/struct.typedef.txt"),
    )?;
    env.add_template(
        "typedef_templates/enum_with_payloads.typedef.txt",
        include_str!("typedef_templates/enum_with_payloads.typedef.txt"),
    )?;
    env.add_template(
        "typedef_templates/enum_without_payloads.typedef.txt",
        include_str!("typedef_templates/enum_without_payloads.typedef.txt"),
    )?;
    let mut non_testing_ctx = SwiftMetadataContext::default();
    let mut testing_ctx = SwiftMetadataContext::default();
    for item in FFI_ITEMS.iter() {
        (item.apply)(
            if item.module_path.starts_with("libsignal_bridge_testing") {
                &mut testing_ctx
            } else {
                &mut non_testing_ctx
            },
        );
    }

    remove_all_checked(
        &mut testing_ctx.derived_types,
        &non_testing_ctx.derived_types,
    );
    remove_all_checked(
        &mut testing_ctx.derived_arg_converters,
        &non_testing_ctx.derived_arg_converters,
    );
    remove_all_checked(
        &mut testing_ctx.derived_return_converters,
        &non_testing_ctx.derived_return_converters,
    );
    remove_all_checked(
        &mut testing_ctx.ffi_borrowed_slice_cons,
        &non_testing_ctx.ffi_borrowed_slice_cons,
    );
    remove_all_checked(
        &mut testing_ctx.ffi_owned_buffer_of_max_aligned_project,
        &non_testing_ctx.ffi_owned_buffer_of_max_aligned_project,
    );

    if args.dump_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&std::collections::BTreeMap::from_iter([
                ("testing", &testing_ctx),
                ("non_testing", &non_testing_ctx),
            ]))?
        );
        return Ok(());
    }

    {
        // Make sure that types agree between testing and non-testing
        for (k, v) in testing_ctx.c_types.iter() {
            if let Some(v2) = non_testing_ctx.c_types.get(k) {
                assert_eq!(v2, v);
            }
        }
        // Make sure that types that are spelled the same are the same
        let unit_ty = RustType::of::<()>();
        let c_void_ty = RustType::of::<std::ffi::c_void>();
        let mut type_name2rust = BTreeMap::new();
        for (k, v) in testing_ctx
            .c_types
            .iter()
            .chain(non_testing_ctx.c_types.iter())
        {
            if k == &unit_ty || k == &c_void_ty {
                // () and std::ffi::c_void have the same spelling
                continue;
            }
            match type_name2rust.entry(v.type_name.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(*k);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    assert_eq!(entry.get(), k);
                }
            }
        }
        let mut visited_types = BTreeSet::new();
        for (mut hdr, ctx, dst) in [
            (
                NON_TESTING_HEADER_H.to_string(),
                &non_testing_ctx,
                "./swift/Sources/SignalFfi/signal_ffi.h",
            ),
            (
                TESTING_HEADER_H.to_string(),
                &testing_ctx,
                "./swift/Sources/SignalFfi/signal_ffi_testing.h",
            ),
        ] {
            for ty in ctx.c_types.keys().copied() {
                emit_utility_typedefs(&env, &mut hdr, &mut visited_types, &ctx.c_types, ty);
            }
            for (name, func) in ctx.c_functions.iter() {
                emit_c_function(&mut hdr, name, func);
            }
            hdr.push_str(&ctx.c_extra_typedefs.iter().join("\n"));
            let dst = PathBuf::from(dst);
            let hdr = prettify_c(&hdr);
            if args.verify {
                anyhow::ensure!(
                    std::fs::read_to_string(&dst)? == hdr,
                    "{dst:?} is not up-to-date"
                );
            } else {
                std::fs::write(&dst, hdr)?;
            }
        }
    }

    for testing in [false, true] {
        let code = env.get_template("NativeNice.swift.in")?.render(context! {
            non_testing_ctx => non_testing_ctx,
            testing_ctx => testing_ctx,
            testing => testing,
        })?;
        let dst = PathBuf::from(if testing {
            "./swift/Tests/LibSignalClientTests/NativeTestingNice.swift"
        } else {
            "./swift/Sources/LibSignalClient/NativeNice.swift"
        });
        if !args.verify {
            // If we're not verifying, write the initial code to disk to help us debug syntax errors.
            std::fs::write(&dst, code.as_bytes())?;
        }
        let (r, mut w) = std::io::pipe()?;
        std::thread::spawn(move || w.write_all(code.as_bytes()).expect("write succeeds"));
        let out = Command::new("swift")
            .arg("format")
            .arg("-")
            .stdin(r)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()?;
        anyhow::ensure!(out.status.success(), "swift formatting failed");
        let code = String::from_utf8(out.stdout)?;
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
