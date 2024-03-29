//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ReceiptCredentialRequest {
    pub(crate) reserved: ReservedByte,
    pub(crate) public_key: crypto::receipt_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::receipt_credential_request::Ciphertext,
    // Note that unlike ProfileKeyCredentialRequest, we don't have a proof. This is because our only
    // "blinded" attribute is the receipt serial number, which is just a random number generated by
    // the client. Whether or not the server is willing to issue a receipt credential doesn't depend
    // on any properties of that serial number.
    //
    // (We could still prove that `public_key` and `ciphertext.D1` were generated according to
    // zkgroup's "blinding" protocol, but that only helps guarantee that the client will be able to
    // decrypt the resulting blinded credential and get a valid credential back, and if the client
    // wants to waste everybody's time by getting the server to issue a credential that it can't
    // use, so be it.)
}
