//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::RwLock;

use derive_where::derive_where;
use prost::bytes::{Buf as _, BufMut as _};

#[derive_where(Default)]
pub struct Decoder<T>(PhantomData<fn() -> T>);

impl<T: serde::de::DeserializeOwned> tonic::codec::Decoder for Decoder<T> {
    type Item = T;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Some(
            serde_json::from_reader(src.reader()).map_err(std::io::Error::from)?,
        ))
    }
}

#[derive_where(Default)]
pub struct Encoder<T>(PhantomData<fn(T)>);

impl<T: serde::Serialize> tonic::codec::Encoder for Encoder<T> {
    type Item = T;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        Ok(serde_json::to_writer(dst.writer(), &item).map_err(std::io::Error::from)?)
    }
}

#[derive_where(Default)]
pub struct Codec<T, U>(PhantomData<(Encoder<T>, Decoder<U>)>);

impl<T, U> tonic::codec::Codec for Codec<T, U>
where
    T: serde::Serialize + Send + 'static,
    U: serde::de::DeserializeOwned + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = Encoder<T>;
    type Decoder = Decoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        Encoder::default()
    }

    fn decoder(&mut self) -> Self::Decoder {
        Decoder::default()
    }
}

pub struct MaybeJson<T> {
    json: bool,
    fallback: T,
}

/// An alias compatible with tonic-build's `codec_path` option.
pub type JsonOrProstCodec<T, U> = MaybeJson<tonic_prost::ProstCodec<T, U>>;

// From https://doc.rust-lang.org/std/collections/struct.HashSet.html#usage-in-const-and-static
// A HashSet without a random seed, so it can be `const`.
static RUNTIMES_WITH_JSON_MODE: RwLock<
    HashSet<tokio::runtime::Id, std::hash::BuildHasherDefault<std::hash::DefaultHasher>>,
> = RwLock::new(HashSet::with_hasher(std::hash::BuildHasherDefault::new()));

pub fn set_json_mode_for_tokio_runtime(runtime: &tokio::runtime::Handle, json_mode: bool) {
    let mut state = RUNTIMES_WITH_JSON_MODE.write().expect("not poisoned");
    let id = runtime.id();
    if json_mode {
        state.insert(id);
    } else {
        state.remove(&id);
    }
}

impl<T: Default> Default for MaybeJson<T> {
    fn default() -> Self {
        let json_mode_active = tokio::runtime::Handle::try_current()
            .ok()
            .and_then(|rt| {
                let id = rt.id();
                let state = RUNTIMES_WITH_JSON_MODE.read().ok()?;
                Some(state.contains(&id))
            })
            .unwrap_or_default();
        Self {
            json: json_mode_active,
            fallback: Default::default(),
        }
    }
}

impl<T, U, C> tonic::codec::Codec for MaybeJson<C>
where
    T: serde::Serialize + Send + 'static,
    U: serde::de::DeserializeOwned + Send + 'static,
    C: tonic::codec::Codec<Encode = T, Decode = U>,
{
    type Encode = T;
    type Decode = U;
    type Encoder = MaybeJson<C::Encoder>;
    type Decoder = MaybeJson<C::Decoder>;

    fn encoder(&mut self) -> Self::Encoder {
        MaybeJson {
            json: self.json,
            fallback: self.fallback.encoder(),
        }
    }

    fn decoder(&mut self) -> Self::Decoder {
        MaybeJson {
            json: self.json,
            fallback: self.fallback.decoder(),
        }
    }
}

impl<C> tonic::codec::Encoder for MaybeJson<C>
where
    C: tonic::codec::Encoder<Item: serde::Serialize, Error = tonic::Status>,
{
    type Item = C::Item;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        if self.json {
            Encoder::default().encode(item, dst)
        } else {
            self.fallback.encode(item, dst)
        }
    }
}

impl<C> tonic::codec::Decoder for MaybeJson<C>
where
    C: tonic::codec::Decoder<Item: serde::de::DeserializeOwned, Error = tonic::Status>,
{
    type Item = C::Item;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if self.json {
            Decoder::default().decode(src)
        } else {
            self.fallback.decode(src)
        }
    }
}
