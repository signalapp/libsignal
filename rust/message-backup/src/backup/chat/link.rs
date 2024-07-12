//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::time::Timestamp;

use crate::proto::backup as proto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LinkPreview {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub date: Option<Timestamp>,
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum LinkPreviewError {}

impl TryFrom<proto::LinkPreview> for LinkPreview {
    type Error = LinkPreviewError;

    fn try_from(value: proto::LinkPreview) -> Result<Self, Self::Error> {
        let proto::LinkPreview {
            url,
            title,
            description,
            date,
            special_fields: _,
            // TODO validate this field
            image: _,
        } = value;
        let date = date.map(|d| Timestamp::from_millis(d, "LinkPreview.date"));

        Ok(Self {
            url,
            title,
            description,
            date,
        })
    }
}
