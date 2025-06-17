//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use http::{HeaderName, HeaderValue};

mod error;
mod request;
// TODO remove this once the types and traits don't need to be exposed.
pub(crate) use request::*;

use crate::ws::JSON_CONTENT_TYPE;

const CONTENT_TYPE_JSON: (HeaderName, HeaderValue) =
    (http::header::CONTENT_TYPE, JSON_CONTENT_TYPE);
