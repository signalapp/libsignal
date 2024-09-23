//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;

pub const SIGNAL_ROOT_CERTIFICATES: RootCertificates =
    RootCertificates::FromDer(Cow::Borrowed(SIGNAL_ROOT_CERT_DER));

pub use libsignal_net_infra::certs::RootCertificates;

const SIGNAL_ROOT_CERT_DER: &[u8] = include_bytes!("../res/signal.cer");
