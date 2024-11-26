//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Protobuf unknown field searching.

#[cfg(test)]
mod visit_dyn;

pub(crate) mod visit_static;

/// Formatter for a sequence of [`PathPart`]s.
///
/// Provides a custom [`std::fmt::Display`] impl.
pub struct FormatPath<P>(pub P);

impl std::fmt::Display for FormatPath<&[PathPart]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut it = self.0.iter().peekable();
        while let Some(part) = it.next() {
            write!(f, "{}", part)?;
            if it.peek().is_some() {
                write!(f, ".")?
            }
        }

        Ok(())
    }
}

/// Protobuf message path component.
#[derive(Clone, Debug, Eq, PartialEq, displaydoc::Display)]
pub enum PathPart {
    /// {field_name}[{index}]
    Repeated { field_name: String, index: usize },
    /// {field_name}
    Field { field_name: String },
    /// {field_name}[{key}]
    MapValue { field_name: String, key: String },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, displaydoc::Display)]
pub enum UnknownValue {
    /// enum value {number}
    EnumValue { number: i32 },
    /// field with tag {tag}
    Field { tag: u32 },
}

/// A path within a protobuf message.
///
/// Implemented as a singly linked list to avoid allocation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Path<'a> {
    Root,
    Branch {
        parent: &'a Path<'a>,
        field_name: &'a str,
        part: Part<'a>,
    },
}

/// The part of a logical field that is being referenced.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Part<'a> {
    Field,
    MapValue { key: MapKey<'a> },
    Repeated { index: usize },
}

/// Key in a protobuf map field.
#[derive(Copy, Clone, Debug, Eq, PartialEq, displaydoc::Display)]
pub(crate) enum MapKey<'a> {
    /// {0}
    U32(u32),
    /// {0}
    U64(u64),
    /// {0}
    I32(i32),
    /// {0}
    I64(i64),
    /// {0}
    Bool(bool),
    /// {0:?}
    String(&'a str),
}

macro_rules! impl_map_key_from {
    ($ty:ty, $constructor:ident $(, $maybe_borrow:tt)?) => {
        impl<'a> From<&'a $ty> for MapKey<'a> {
            fn from(value: &'a $ty) -> Self {
                Self::$constructor($($maybe_borrow)? *value)
            }
        }
    };
}
impl_map_key_from!(u32, U32);
impl_map_key_from!(u64, U64);
impl_map_key_from!(i32, I32);
impl_map_key_from!(i64, I64);
impl_map_key_from!(bool, Bool);
impl_map_key_from!(String, String, &);

impl Path<'_> {
    fn owned_parts(&self) -> Vec<PathPart> {
        let mut head = self;
        let mut output = Vec::new();

        // Standard linked-list traversal.
        while let Path::Branch {
            parent,
            part,
            field_name,
        } = head
        {
            let field_name = field_name.to_string();
            output.push(PathPart::from_part(part, field_name));
            head = parent;
        }

        // Since each `Path` points at its parent, the list is lowest-to-highest
        // path part before reversal.
        output.reverse();
        output
    }
}

impl PathPart {
    fn from_part(part: &Part<'_>, field_name: String) -> Self {
        match part {
            Part::Field => Self::Field { field_name },
            Part::MapValue { key } => Self::MapValue {
                field_name,
                key: key.to_string(),
            },
            Part::Repeated { index } => Self::Repeated {
                field_name,
                index: *index,
            },
        }
    }
}

/// Visitor for unknown fields on a [`protobuf::Message`].
pub trait VisitUnknownFields {
    /// Calls the visitor for each unknown field in the message.
    fn visit_unknown_fields<F: UnknownFieldVisitor>(&self, visitor: F);
}

/// Convenience "alias" for a callable visitor.
pub trait UnknownFieldVisitor: FnMut(Vec<PathPart>, UnknownValue) {}
impl<F: FnMut(Vec<PathPart>, UnknownValue)> UnknownFieldVisitor for F {}

impl<M: visit_static::VisitUnknownFields> VisitUnknownFields for M {
    fn visit_unknown_fields<F: UnknownFieldVisitor>(&self, mut visitor: F) {
        visit_static::VisitUnknownFields::visit_unknown_fields(self, Path::Root, &mut visitor);
    }
}

/// Extension trait for [`VisitUnknownFields`] with convenience methods.
pub trait VisitUnknownFieldsExt {
    #[allow(dead_code)]
    fn has_unknown_fields(&self) -> bool;
    fn collect_unknown_fields(&self) -> Vec<(Vec<PathPart>, UnknownValue)>;
    #[allow(dead_code)]
    fn find_unknown_field(&self) -> Option<(Vec<PathPart>, UnknownValue)>;
}

impl<V: VisitUnknownFields> VisitUnknownFieldsExt for V {
    fn has_unknown_fields(&self) -> bool {
        self.find_unknown_field().is_some()
    }

    fn collect_unknown_fields(&self) -> Vec<(Vec<PathPart>, UnknownValue)> {
        let mut found = Vec::new();
        self.visit_unknown_fields(|path, value| {
            found.push((path, value));
        });
        found
    }

    fn find_unknown_field(&self) -> Option<(Vec<PathPart>, UnknownValue)> {
        let mut found = None;
        self.visit_unknown_fields(|path, value| {
            if found.is_none() {
                found = Some((path, value));
            }
        });

        found
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use protobuf::Message;
    use test_case::{test_case, test_matrix};

    use super::*;
    use crate::proto::test as proto;

    trait ProtoWireCast {
        fn wire_cast_as<M: Message>(self) -> M;
    }

    impl<S: Message> ProtoWireCast for S {
        fn wire_cast_as<M: Message>(self) -> M {
            let mut bytes = Vec::new();
            self.write_to_vec(&mut bytes).expect("can serialize");
            M::parse_from_bytes(&bytes).expect("can deserialize")
        }
    }

    const FAKE_BYTES: [u8; 5] = *b"abcde";
    const FAKE_STRING: &str = "fghij";
    const FAKE_INT64: i64 = 49582945;
    const FAKE_REPEATED_UINT64: [u64; 2] = [42, 85];
    const FAKE_ONEOF: proto::test_message::Oneof = proto::test_message::Oneof::OneofBool(false);
    const FAKE_ENUM: proto::TestEnum = proto::TestEnum::TWO;

    impl proto::TestMessage {
        fn fake_data() -> Self {
            Self {
                bytes: FAKE_BYTES.into(),
                string: FAKE_STRING.into(),
                int64: FAKE_INT64,
                repeated_message: vec![proto::TestMessage::default(); 3],
                repeated_uint64: FAKE_REPEATED_UINT64.into(),
                enum_: FAKE_ENUM.into(),
                oneof: Some(FAKE_ONEOF),
                nested_message: Some(proto::TestMessage::default()).into(),
                map: HashMap::from([("key".to_string(), proto::TestMessage::default())]),
                special_fields: Default::default(),
            }
        }
    }

    fn never_visits(_: Vec<PathPart>, _: UnknownValue) {
        unreachable!("unexpectedly visited")
    }

    struct ViaProtoDescriptors<M>(M);
    struct ViaStaticDispatch<M>(M);

    impl VisitUnknownFields for ViaProtoDescriptors<proto::TestMessage> {
        fn visit_unknown_fields<F: UnknownFieldVisitor>(&self, mut visitor: F) {
            visit_dyn::visit_unknown_fields(&self.0, Path::Root, &mut visitor);
        }
    }

    impl VisitUnknownFields for ViaProtoDescriptors<proto::TestMessageWithExtraFields> {
        fn visit_unknown_fields<F: UnknownFieldVisitor>(&self, mut visitor: F) {
            visit_dyn::visit_unknown_fields(&self.0, Path::Root, &mut visitor);
        }
    }

    impl<M: visit_static::VisitUnknownFields> VisitUnknownFields for ViaStaticDispatch<M> {
        fn visit_unknown_fields<F: UnknownFieldVisitor>(&self, mut visitor: F) {
            visit_static::VisitUnknownFields::visit_unknown_fields(
                &self.0,
                Path::Root,
                &mut visitor,
            );
        }
    }

    #[test_matrix(
        (
            proto::TestMessage::default(),
            proto::TestMessage::fake_data(),
            proto::TestMessage::fake_data().wire_cast_as::<proto::TestMessage>(),
            proto::TestMessage::fake_data().wire_cast_as::<proto::TestMessageWithExtraFields>(),
        ),
        (ViaProtoDescriptors, ViaStaticDispatch)
    )]
    fn no_extra_fields<M, V: VisitUnknownFields>(proto: M, to_visitor: impl FnOnce(M) -> V) {
        let visitor = to_visitor(proto);
        visitor.visit_unknown_fields(never_visits);
    }

    macro_rules! modifier {
        ($name:ident, $field:ident = $value:expr) => {
            fn $name(target: &mut proto::TestMessageWithExtraFields) {
                #[allow(unused)]
                use proto::test_message_with_extra_fields::Oneof;
                target.$field = $value;
            }
        };
    }

    modifier!(oneof_extra_int, oneof = Some(Oneof::OneofExtraInt64(32)));
    modifier!(
        oneof_extra_string,
        oneof = Some(Oneof::OneofExtraString("asdf".into()))
    );
    modifier!(
        oneof_extra_message,
        oneof = Some(Oneof::OneofExtraMessage(Box::default()))
    );
    modifier!(extra_string, extra_string = FAKE_STRING.into());
    modifier!(extra_bytes, extra_bytes = FAKE_BYTES.into());
    modifier!(extra_int64, extra_int64 = FAKE_INT64);
    modifier!(
        extra_repeated_message,
        extra_repeated_message = vec![proto::TestMessageWithExtraFields::default(); 4]
    );
    modifier!(
        extra_repeated_uint64,
        extra_repeated_uint64 = FAKE_REPEATED_UINT64.into()
    );
    modifier!(
        extra_enum,
        extra_enum = proto::TestEnumWithExtraVariants::TWO_EXTRA_VARIANTS.into()
    );
    modifier!(
        extra_nested,
        extra_nested_message = Some(proto::TestMessageWithExtraFields::default()).into()
    );
    modifier!(
        extra_map,
        extra_map = HashMap::from([(
            "extra key".to_string(),
            proto::TestMessageWithExtraFields::default()
        )])
    );

    #[test_matrix(
        (
            (oneof_extra_int, UnknownValue::Field {tag: 612}),
            (oneof_extra_string, UnknownValue::Field {tag: 611}),
            (oneof_extra_message, UnknownValue::Field {tag: 610}),
            (extra_string, UnknownValue::Field {tag: 701}),
            (extra_bytes, UnknownValue::Field {tag: 731}),
            (extra_int64, UnknownValue::Field {tag: 711}),
            (extra_repeated_message, UnknownValue::Field {tag: 721}),
            (extra_repeated_uint64, UnknownValue::Field {tag: 741}),
            (extra_enum, UnknownValue::Field {tag: 751}),
            (extra_nested, UnknownValue::Field {tag: 761}),
            (extra_map, UnknownValue::Field {tag: 771}),
        ),
        (ViaProtoDescriptors, ViaStaticDispatch)
    )]
    fn has_unknown_fields_top_level<V: VisitUnknownFields>(
        (modifier, expected_value): (fn(&mut proto::TestMessageWithExtraFields), UnknownValue),
        to_visitor: impl FnOnce(proto::TestMessage) -> V,
    ) {
        let mut message =
            proto::TestMessage::fake_data().wire_cast_as::<proto::TestMessageWithExtraFields>();
        modifier(&mut message);

        let message = message.wire_cast_as::<proto::TestMessage>();
        let visitor = to_visitor(message);

        let (path, value) = visitor.find_unknown_field().expect("has unknown");
        assert_eq!(value, expected_value);

        assert_eq!(path, &[]);
    }

    #[test_case(ViaProtoDescriptors)]
    #[test_case(ViaStaticDispatch)]
    fn unknown_fields_in_nested_message<V: VisitUnknownFields>(
        to_visitor: impl FnOnce(proto::TestMessage) -> V,
    ) {
        let message = proto::TestMessageWithExtraFields {
            nested_message: Some(proto::TestMessageWithExtraFields {
                repeated_message: vec![
                    proto::TestMessageWithExtraFields::default(),
                    proto::TestMessageWithExtraFields {
                        extra_int64: FAKE_INT64,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            })
            .into(),
            map: HashMap::from([(
                "map_key".to_string(),
                proto::TestMessageWithExtraFields {
                    oneof: Some(proto::test_message_with_extra_fields::Oneof::OneofMessage(
                        Box::new(proto::TestMessageWithExtraFields {
                            enum_: proto::TestEnumWithExtraVariants::EXTRA_THREE.into(),
                            ..Default::default()
                        }),
                    )),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let message: proto::TestMessage = message.wire_cast_as();

        const EXPECTED_UNKNOWN: [(&str, UnknownValue); 2] = [
            (
                "nested_message.repeated_message[1]",
                UnknownValue::Field { tag: 711 },
            ),
            (
                "map[\"map_key\"].oneof.oneof_message.enum",
                UnknownValue::EnumValue { number: 3 },
            ),
        ];

        let found: Vec<_> = to_visitor(message)
            .collect_unknown_fields()
            .into_iter()
            .map(|(key, value)| {
                let key = key
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                (key, value)
            })
            .collect();

        assert_eq!(
            HashMap::from_iter(found.iter().map(|(k, v)| (k.as_str(), *v))),
            HashMap::from(EXPECTED_UNKNOWN)
        );
    }
}
