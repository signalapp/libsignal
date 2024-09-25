//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use libsignal_net_infra::certs::RootCertificates;

pub const SIGNAL_ROOT_CERTIFICATES: RootCertificates =
    RootCertificates::FromStaticDers(&[include_bytes!("../res/signal.cer")]);

// GIAG2 cert plus root certs from pki.goog
pub const PROXY_G_ROOT_CERTIFICATES: RootCertificates = RootCertificates::FromStaticDers(&[
    include_bytes!("../res/GIAG2.cer"),
    include_bytes!("../res/GSR2.cer"),
    include_bytes!("../res/GSR4.cer"),
    include_bytes!("../res/GTSR1.cer"),
    include_bytes!("../res/GTSR2.cer"),
    include_bytes!("../res/GTSR3.cer"),
    include_bytes!("../res/GTSR4.cer"),
]);
