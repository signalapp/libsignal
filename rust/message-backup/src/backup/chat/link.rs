//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::TryIntoWith;
use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
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
    /// missing url
    EmptyUrl,
    /// image: {0}
    Image(FilePointerError),
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<C: ReportUnusualTimestamp> TryIntoWith<LinkPreview, C> for proto::LinkPreview {
    type Error = LinkPreviewError;

    fn try_into_with(self, context: &C) -> Result<LinkPreview, Self::Error> {
        let proto::LinkPreview {
            url,
            title,
            image,
            description,
            date,
            special_fields: _,
        } = self;

        if url.is_empty() {
            return Err(LinkPreviewError::EmptyUrl);
        }

        let date = date
            .map(|d| Timestamp::from_millis(d, "LinkPreview.date", context))
            .transpose()?;

        let image = image
            .into_option()
            .map(|file| file.try_into_with(context))
            .transpose()
            .map_err(LinkPreviewError::Image)?;

        Ok(LinkPreview {
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
    use crate::backup::testutil::TestContext;
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
    #[test_case(|x| x.url = "".into() => Err(LinkPreviewError::EmptyUrl); "empty url")]
    #[test_case(|x| x.title = None => Ok(()); "no title")]
    #[test_case(|x| x.title = Some("".into()) => Ok(()); "empty title")]
    #[test_case(|x| x.image = None.into() => Ok(()); "no image")]
    #[test_case(|x| x.image = Some(proto::FilePointer::default()).into() => Err(LinkPreviewError::Image(FilePointerError::NoLocatorInfo)); "invalid image")]
    #[test_case(|x| x.description = None => Ok(()); "no description")]
    #[test_case(|x| x.description = Some("".into()) => Ok(()); "empty description")]
    #[test_case(
        |x| x.date = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(LinkPreviewError::InvalidTimestamp(TimestampError("LinkPreview.date", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn link_preview(
        modifier: impl FnOnce(&mut proto::LinkPreview),
    ) -> Result<(), LinkPreviewError> {
        let mut locator = proto::LinkPreview::test_data();
        modifier(&mut locator);
        locator.try_into_with(&TestContext::default()).map(|_| ())
    }
}
