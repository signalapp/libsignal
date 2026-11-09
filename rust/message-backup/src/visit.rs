//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! A generic visitor over the backup protobuf message types.

/// A generic trait for visiting with state.
///
/// Implementations should destructure every field explicitly, either acting on it, ignoring it, or
/// recursing into it (for sub-messages).
///
/// Note that `oneof`s are handled in the parent type rather than as a distinct impl of `Visit`.
/// This is purely a stylistic choice for slightly more compact code; both ways would work.
///
/// There's no built-in traversal here, for a few reasons:
/// - It makes it clearer that a visitor is supposed to act on or ignore every field explicitly.
/// - If there's ever a reason for a visitor to *not* recurse into a field, it's easier to do so.
pub trait Visit<V> {
    fn accept(&mut self, visitor: &mut V);
}

/// Recurse into a possibly-absent sub-message.
impl<V, T: Visit<V>> Visit<V> for protobuf::MessageField<T> {
    fn accept(&mut self, visitor: &mut V) {
        if let Some(x) = self.as_mut() {
            x.accept(visitor);
        }
    }
}

/// Recurse into a `repeated` sub-message.
impl<V, T: Visit<V>> Visit<V> for Vec<T> {
    fn accept(&mut self, visitor: &mut V) {
        self.iter_mut().for_each(|x| x.accept(visitor));
    }
}
