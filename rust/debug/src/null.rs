//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
pub(super) const NAME: &str = "null";

pub(super) struct TraceSectionGuard;
impl TraceSectionGuard {
    pub(super) fn from_section(_section: &super::Section) -> Self {
        TraceSectionGuard
    }
}
