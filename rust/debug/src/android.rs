//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::cell::Cell;
use std::ffi::{CStr, c_char};
use std::marker::PhantomData;
use std::num::NonZeroI32;

pub(super) const NAME: &str = "android";

#[link(name = "android", kind = "dylib")]
unsafe extern "C" {
    // https://developer.android.com/ndk/reference/group/tracing
    fn ATrace_beginSection(section_name: *const c_char);
    fn ATrace_endSection();
    fn ATrace_isEnabled() -> bool;
}

#[derive(Clone, Copy, Debug)]
struct TraceState {
    next_id: u64,
    current_id: u64,
}

thread_local! {
    static TRACE_STATE: Cell<TraceState> = const { Cell::new(TraceState {
        next_id: 1,
        current_id: 0,
    }) };
}

#[derive(Debug)]
pub(super) struct TraceSectionGuard {
    enabled: bool,
    snapshot: TraceState,
    // This guard shouldn't be Send or Sync
    phantom: PhantomData<*mut ()>,
}

impl TraceSectionGuard {
    pub(super) fn from_section(section: &super::Section) -> Self {
        let snapshot = TRACE_STATE.with(|trace_state| {
            let snapshot = trace_state.get();
            trace_state.set(TraceState {
                next_id: snapshot.next_id + 1,
                current_id: snapshot.next_id,
            });
            snapshot
        });
        if !unsafe { ATrace_isEnabled() } {
            return TraceSectionGuard {
                enabled: false,
                snapshot,
                phantom: PhantomData,
            };
        }
        unsafe {
            ATrace_beginSection(section.name.as_ptr());
        }
        let out = TraceSectionGuard {
            enabled: true,
            phantom: PhantomData,
            snapshot,
        };
        out
    }
}

impl std::ops::Drop for TraceSectionGuard {
    fn drop(&mut self) {
        TRACE_STATE.with(|trace_state| {
            let snapshot = trace_state.get();
            assert_eq!(snapshot.current_id, self.snapshot.next_id);
            trace_state.set(TraceState {
                next_id: snapshot.next_id,
                current_id: self.snapshot.current_id,
            });
        });
        if self.enabled && unsafe { ATrace_isEnabled() } {
            unsafe {
                ATrace_endSection();
            }
        }
    }
}
