//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use crate::infra::HttpRequestDecorator;
use crate::utils::basic_authorization;

pub trait HttpBasicAuth {
    fn username(&self) -> &str;
    fn password(&self) -> std::borrow::Cow<str>;
}

impl<T: HttpBasicAuth> From<T> for HttpRequestDecorator {
    fn from(value: T) -> Self {
        HttpRequestDecorator::HeaderAuth(basic_authorization(value.username(), &value.password()))
    }
}
