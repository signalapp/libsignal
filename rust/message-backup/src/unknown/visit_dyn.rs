//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Unknown field searching via dynamic traversal of protubuf message
//! descriptors.

use protobuf::reflect::{ReflectFieldRef, ReflectValueRef};
use protobuf::MessageDyn;

use crate::unknown::{MapKey, Part, Path, UnknownFieldVisitor, UnknownValue};

pub(super) fn visit_unknown_fields(
    message: &dyn MessageDyn,
    path: Path<'_>,
    // It seems like this could be just `impl UnknownFieldVisitor`, but
    // because this function is indirectly recursive and fans out, making it
    // an owned type (and recursing with `&mut visitor`) causes the compiler
    // to fail to determine whether `&mut &mut .... &mut impl
    // UnknownFieldVisitor` implements `UnknownFieldVisitor`.
    visitor: &mut impl UnknownFieldVisitor,
) {
    for (tag, _value) in message.unknown_fields_dyn() {
        visitor(path.owned_parts(), UnknownValue::Field { tag })
    }

    for field in message.descriptor_dyn().fields() {
        let containing_oneof = field.containing_oneof();
        let path = match containing_oneof.as_ref() {
            None => path,
            Some(oneof) => Path::Branch {
                parent: &path,
                field_name: oneof.name(),
                part: Part::Field,
            },
        };
        visit_child_unknown_fields(field.get_reflect(message), path, field.name(), visitor)
    }
}

fn visit_child_unknown_fields<'s>(
    field: ReflectFieldRef<'s>,
    parent_path: Path<'s>,
    field_name: &'s str,
    visitor: &mut impl UnknownFieldVisitor,
) {
    let make_path = |part| Path::Branch {
        parent: &parent_path,
        field_name,
        part,
    };

    match field {
        ReflectFieldRef::Optional(value) => {
            let Some(value) = value.value() else {
                return;
            };
            visit_field(value, visitor, make_path(Part::Field))
        }
        ReflectFieldRef::Repeated(values) => {
            for (index, value) in values.into_iter().enumerate() {
                visit_field(value, visitor, make_path(Part::Repeated { index }));
            }
        }
        ReflectFieldRef::Map(values) => {
            for (key, value) in &values {
                let key = key.into();
                visit_field(value, visitor, make_path(Part::MapValue { key }));
            }
        }
    }
}

fn visit_field<'s>(
    value: ReflectValueRef<'s>,
    visitor: &mut impl UnknownFieldVisitor,
    path: Path<'s>,
) {
    match value {
        ReflectValueRef::U32(_)
        | ReflectValueRef::U64(_)
        | ReflectValueRef::I32(_)
        | ReflectValueRef::I64(_)
        | ReflectValueRef::F32(_)
        | ReflectValueRef::F64(_)
        | ReflectValueRef::Bool(_)
        | ReflectValueRef::String(_)
        | ReflectValueRef::Bytes(_) => {}
        ReflectValueRef::Enum(descriptor, number) => {
            if descriptor.value_by_number(number).is_none() {
                visitor(path.owned_parts(), UnknownValue::EnumValue { number })
            }
        }
        ReflectValueRef::Message(message) => {
            let message: &dyn MessageDyn = &*message;
            visit_unknown_fields(message, path, visitor)
        }
    }
}

impl<'a> From<ReflectValueRef<'a>> for MapKey<'a> {
    fn from(value: ReflectValueRef<'a>) -> Self {
        match value {
            ReflectValueRef::U32(v) => Self::U32(v),
            ReflectValueRef::U64(v) => Self::U64(v),
            ReflectValueRef::I32(v) => Self::I32(v),
            ReflectValueRef::I64(v) => Self::I64(v),
            ReflectValueRef::Bool(v) => Self::Bool(v),
            ReflectValueRef::String(v) => Self::String(v),
            v @ ReflectValueRef::F32(_)
            | v @ ReflectValueRef::F64(_)
            | v @ ReflectValueRef::Bytes(_)
            | v @ ReflectValueRef::Enum(_, _)
            | v @ ReflectValueRef::Message(_) => {
                // Per the protobuf docs:
                // > key_type can be any integral or string type (so, any scalar
                // > type except for floating point types and bytes). Note that
                // > enum is not a valid key_type."
                unreachable!("unexpected key {v}")
            }
        }
    }
}
