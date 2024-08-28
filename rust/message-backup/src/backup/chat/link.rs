//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::time::Timestamp;
use crate::proto::backup as proto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LinkPreview {
    pub url: String,
    pub title: Option<String>,
    pub image: Option<FilePointer>,
    pub description: Option<String>,
    pub date: Option<Timestamp>,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum LinkPreviewError {
    /// image: {0}
    Image(FilePointerError),
}

impl TryFrom<proto::LinkPreview> for LinkPreview {
    type Error = LinkPreviewError;

    fn try_from(value: proto::LinkPreview) -> Result<Self, Self::Error> {
        let proto::LinkPreview {
            url,
            title,
            image,
            description,
            date,
            special_fields: _,
        } = value;

        let date = date.map(|d| Timestamp::from_millis(d, "LinkPreview.date"));

        let image = image
            .into_option()
            .map(FilePointer::try_from)
            .transpose()
            .map_err(LinkPreviewError::Image)?;

        Ok(Self {
            url,
            title,
            image,
            description,
            date,
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl proto::LinkPreview {
        fn test_data() -> Self {
            Self {
                url: "https://signal.org".into(),
                title: Some("Signal".into()),
                image: Some(proto::FilePointer::test_data()).into(),
                description: Some("Speak Freely".into()),
                date: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                special_fields: Default::default(),
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.url = "".into() => Ok(()); "empty url")]
    #[test_case(|x| x.title = None => Ok(()); "no title")]
    #[test_case(|x| x.title = Some("".into()) => Ok(()); "empty title")]
    #[test_case(|x| x.image = None.into() => Ok(()); "no image")]
    #[test_case(|x| x.image = Some(proto::FilePointer::default()).into() => Err(LinkPreviewError::Image(FilePointerError::NoLocator)); "invalid image")]
    #[test_case(|x| x.description = None => Ok(()); "no description")]
    #[test_case(|x| x.description = Some("".into()) => Ok(()); "empty description")]
    fn link_preview(
        modifier: impl FnOnce(&mut proto::LinkPreview),
    ) -> Result<(), LinkPreviewError> {
        let mut locator = proto::LinkPreview::test_data();
        modifier(&mut locator);
        LinkPreview::try_from(locator).map(|_| ())
    }
}
