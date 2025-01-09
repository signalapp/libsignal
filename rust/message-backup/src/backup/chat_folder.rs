//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use intmap::IntMap;
use itertools::Itertools;

use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::{DestinationKind, MinimalRecipientData};
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

/// Validated version of [`proto::ChatFolder`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatFolder<Recipient> {
    All,
    Custom {
        name: String,
        show_only_unread: bool,
        show_muted_chats: bool,
        include_all_individual_chats: bool,
        include_all_group_chats: bool,
        #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
        included_recipients: UnorderedList<Recipient>,
        #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
        excluded_recipients: UnorderedList<Recipient>,
        // While this isn't *enforced* for an enum variant, hopefully it's still a good hint.
        _limit_construction_to_module: (),
    },
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatFolderError {
    /// unknown type {0}
    UnknownType(i32),
    /// ALL folder name must be empty
    AllFolderInvalidName,
    /// ALL folder must not only show unread
    AllFolderMustNotShowOnlyUnread,
    /// ALL folder must show muted chats
    AllFolderMustShowMuted,
    /// ALL folder must include individual chats by default
    AllFolderMustIncludeIndividualChats,
    /// ALL folder must include group chats by default
    AllFolderMustIncludeGroupChats,
    /// ALL folder must not have specific includes
    AllFolderMustNotHaveSpecificIncludes,
    /// ALL folder must not exclude chats
    AllFolderMustNotExcludeChats,
    /// missing name for non-ALL folder
    MissingName,
    /// included member {0:?} is unknown
    IncludedMemberUnknown(RecipientId),
    /// included member {0:?} appears multiple times
    IncludedMemberDuplicate(RecipientId),
    /// included member {0:?} is a {1:?}
    IncludedMemberWrongKind(RecipientId, DestinationKind),
    /// excluded member {0:?} is unknown
    ExcludedMemberUnknown(RecipientId),
    /// excluded member {0:?} appears multiple times
    ExcludedMemberDuplicate(RecipientId),
    /// excluded member {0:?} is a {1:?}
    ExcludedMemberWrongKind(RecipientId, DestinationKind),
    /// recipient {0:?} is in both the included and excluded lists
    MemberIsBothIncludedAndExcluded(RecipientId),
}

impl<R> ChatFolder<R> {
    fn validate_all_chat_folder(item: proto::ChatFolder) -> Result<Self, ChatFolderError> {
        let proto::ChatFolder {
            name,
            showOnlyUnread,
            showMutedChats,
            includeAllIndividualChats,
            includeAllGroupChats,
            folderType,
            includedRecipientIds,
            excludedRecipientIds,
            special_fields: _,
        } = item;

        assert_eq!(
            folderType.enum_value(),
            Ok(proto::chat_folder::FolderType::ALL),
            "should not call this method on arbitrary chat folders"
        );

        if !name.is_empty() {
            return Err(ChatFolderError::AllFolderInvalidName);
        }
        if showOnlyUnread {
            return Err(ChatFolderError::AllFolderMustNotShowOnlyUnread);
        }
        if !showMutedChats {
            return Err(ChatFolderError::AllFolderMustShowMuted);
        }
        if !includeAllIndividualChats {
            return Err(ChatFolderError::AllFolderMustIncludeIndividualChats);
        }
        if !includeAllGroupChats {
            return Err(ChatFolderError::AllFolderMustIncludeGroupChats);
        }
        if !includedRecipientIds.is_empty() {
            return Err(ChatFolderError::AllFolderMustNotHaveSpecificIncludes);
        }
        if !excludedRecipientIds.is_empty() {
            return Err(ChatFolderError::AllFolderMustNotExcludeChats);
        }

        Ok(Self::All)
    }
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R>>
    TryFromWith<proto::ChatFolder, C> for ChatFolder<R>
{
    type Error = ChatFolderError;
    fn try_from_with(item: proto::ChatFolder, context: &C) -> Result<Self, Self::Error> {
        match item.folderType.enum_value_or_default() {
            proto::chat_folder::FolderType::UNKNOWN => {
                return Err(ChatFolderError::UnknownType(item.folderType.value()));
            }
            proto::chat_folder::FolderType::ALL => {
                return Self::validate_all_chat_folder(item);
            }
            proto::chat_folder::FolderType::CUSTOM => {}
        }

        let proto::ChatFolder {
            name,
            showOnlyUnread,
            showMutedChats,
            includeAllIndividualChats,
            includeAllGroupChats,
            folderType: _,
            includedRecipientIds,
            excludedRecipientIds,
            special_fields: _,
        } = item;

        if name.is_empty() {
            return Err(ChatFolderError::MissingName);
        }

        let mut seen_included_members = IntMap::default();
        let included_recipients = includedRecipientIds
            .into_iter()
            .map(|id| {
                let id = RecipientId(id);
                if seen_included_members.insert(id, ()).is_some() {
                    return Err(ChatFolderError::IncludedMemberDuplicate(id));
                }
                let (data, recipient) = context
                    .lookup_pair(&id)
                    .ok_or(ChatFolderError::IncludedMemberUnknown(id))?;
                let kind = data.as_ref();
                match kind {
                    DestinationKind::Contact | DestinationKind::Self_ | DestinationKind::Group => {
                        Ok(recipient.clone())
                    }
                    DestinationKind::ReleaseNotes
                    | DestinationKind::DistributionList
                    | DestinationKind::CallLink => {
                        Err(ChatFolderError::IncludedMemberWrongKind(id, *kind))
                    }
                }
            })
            .try_collect()?;

        let mut seen_excluded_members = IntMap::default();
        let excluded_recipients = excludedRecipientIds
            .into_iter()
            .map(|id| {
                let id = RecipientId(id);
                if seen_excluded_members.insert(id, ()).is_some() {
                    return Err(ChatFolderError::ExcludedMemberDuplicate(id));
                }
                if seen_included_members.get(id).is_some() {
                    return Err(ChatFolderError::MemberIsBothIncludedAndExcluded(id));
                }
                let (data, recipient) = context
                    .lookup_pair(&id)
                    .ok_or(ChatFolderError::ExcludedMemberUnknown(id))?;
                let kind = data.as_ref();
                match kind {
                    DestinationKind::Contact | DestinationKind::Self_ | DestinationKind::Group => {
                        Ok(recipient.clone())
                    }
                    DestinationKind::ReleaseNotes
                    | DestinationKind::DistributionList
                    | DestinationKind::CallLink => {
                        Err(ChatFolderError::ExcludedMemberWrongKind(id, *kind))
                    }
                }
            })
            .try_collect()?;

        Ok(Self::Custom {
            name,
            show_only_unread: showOnlyUnread,
            show_muted_chats: showMutedChats,
            include_all_individual_chats: includeAllIndividualChats,
            include_all_group_chats: includeAllGroupChats,
            included_recipients,
            excluded_recipients,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;
    use crate::backup::TryIntoWith as _;

    impl proto::ChatFolder {
        pub(crate) fn test_data() -> Self {
            Self {
                name: "Test".into(),
                showOnlyUnread: false,
                showMutedChats: true,
                includeAllIndividualChats: true,
                includeAllGroupChats: true,
                folderType: proto::chat_folder::FolderType::CUSTOM.into(),
                includedRecipientIds: vec![],
                excludedRecipientIds: vec![TestContext::CONTACT_ID.0],
                ..Default::default()
            }
        }

        pub(crate) fn all_folder_data() -> Self {
            Self {
                name: "".into(),
                showOnlyUnread: false,
                showMutedChats: true,
                includeAllIndividualChats: true,
                includeAllGroupChats: true,
                folderType: proto::chat_folder::FolderType::ALL.into(),
                includedRecipientIds: vec![],
                excludedRecipientIds: vec![],
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_chat_folder() {
        assert_eq!(
            proto::ChatFolder::test_data().try_into_with(&TestContext::default()),
            Ok(ChatFolder::<FullRecipientData>::Custom {
                name: "Test".into(),
                show_only_unread: false,
                show_muted_chats: true,
                include_all_individual_chats: true,
                include_all_group_chats: true,
                included_recipients: vec![].into(),
                excluded_recipients: vec![TestContext::contact_recipient().clone()].into(),
                _limit_construction_to_module: (),
            })
        )
    }

    #[test_case(|x| x.name = "".into() => Err(ChatFolderError::MissingName); "empty name")]
    #[test_case(|x| x.excludedRecipientIds.clear() => Ok(()); "no exclusions is okay")]
    #[test_case(|x| x.excludedRecipientIds.push(TestContext::GROUP_ID.0) => Ok(()); "excluding groups is okay")]
    #[test_case(|x| x.excludedRecipientIds.push(TestContext::SELF_ID.0) => Ok(()); "excluding Self is okay")]
    #[test_case(|x| x.excludedRecipientIds.push(TestContext::CALL_LINK_ID.0) => Err(ChatFolderError::ExcludedMemberWrongKind(TestContext::CALL_LINK_ID, DestinationKind::CallLink)); "excluding call links is not okay")]
    #[test_case(|x| x.excludedRecipientIds.push(TestContext::CONTACT_ID.0) => Err(ChatFolderError::ExcludedMemberDuplicate(TestContext::CONTACT_ID)); "duplicate exclusion")]
    #[test_case(|x| x.excludedRecipientIds.push(TestContext::NONEXISTENT_ID.0) => Err(ChatFolderError::ExcludedMemberUnknown(TestContext::NONEXISTENT_ID)); "unknown exclusion")]
    #[test_case(|x| {
        x.includeAllGroupChats = false;
        x.includedRecipientIds.push(TestContext::GROUP_ID.0);
    } => Ok(()); "explicit inclusion")]
    #[test_case(|x| {
        x.includeAllGroupChats = false;
        x.includedRecipientIds.push(TestContext::GROUP_ID.0);
        x.includedRecipientIds.push(TestContext::GROUP_ID.0);
    } => Err(ChatFolderError::IncludedMemberDuplicate(TestContext::GROUP_ID)); "duplicate inclusion")]
    #[test_case(|x| x.includedRecipientIds.push(TestContext::NONEXISTENT_ID.0) => Err(ChatFolderError::IncludedMemberUnknown(TestContext::NONEXISTENT_ID)); "unknown inclusion")]
    #[test_case(|x| x.includedRecipientIds.push(TestContext::CALL_LINK_ID.0) => Err(ChatFolderError::IncludedMemberWrongKind(TestContext::CALL_LINK_ID, DestinationKind::CallLink)); "including call links is not okay")]
    #[test_case(|x| x.includedRecipientIds.push(TestContext::CONTACT_ID.0) => Err(ChatFolderError::MemberIsBothIncludedAndExcluded(TestContext::CONTACT_ID)); "member in both lists")]
    #[test_case(|x| x.includedRecipientIds.push(TestContext::GROUP_ID.0) => Ok(()); "include a group even though all groups are included by default")]
    fn folder(mutator: fn(&mut proto::ChatFolder)) -> Result<(), ChatFolderError> {
        let mut folder = proto::ChatFolder::test_data();
        mutator(&mut folder);

        folder
            .try_into_with(&TestContext::default())
            .map(|_: ChatFolder<FullRecipientData>| ())
    }

    #[test]
    fn valid_all_folder() {
        assert_eq!(
            proto::ChatFolder::all_folder_data().try_into_with(&TestContext::default()),
            Ok(ChatFolder::<FullRecipientData>::All)
        )
    }

    #[test_case(|x| x.name = "Test".into() => Err(ChatFolderError::AllFolderInvalidName); "must be unnamed")]
    #[test_case(|x| x.showOnlyUnread = true => Err(ChatFolderError::AllFolderMustNotShowOnlyUnread); "must not show only unread")]
    #[test_case(|x| x.showMutedChats = false => Err(ChatFolderError::AllFolderMustShowMuted); "must show muted chats")]
    #[test_case(|x| x.includeAllIndividualChats = false => Err(ChatFolderError::AllFolderMustIncludeIndividualChats); "must show 1:1 chats")]
    #[test_case(|x| x.includeAllGroupChats = false => Err(ChatFolderError::AllFolderMustIncludeGroupChats); "must show group chats")]
    #[test_case(|x| x.includedRecipientIds = vec![9999] => Err(ChatFolderError::AllFolderMustNotHaveSpecificIncludes); "must not have includes")]
    #[test_case(|x| x.excludedRecipientIds = vec![9999] => Err(ChatFolderError::AllFolderMustNotExcludeChats); "must not have excludes")]
    fn all_folder(mutator: fn(&mut proto::ChatFolder)) -> Result<(), ChatFolderError> {
        let mut folder = proto::ChatFolder::all_folder_data();
        mutator(&mut folder);

        folder
            .try_into_with(&TestContext::default())
            .map(|folder: ChatFolder<FullRecipientData>| assert_matches!(folder, ChatFolder::All))
    }
}
