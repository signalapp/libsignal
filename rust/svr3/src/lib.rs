//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
mod oprf;
mod ppss;
pub use ppss::MaskedShareSet;
mod errors;
mod proto;
pub use errors::{Error, OPRFError, PPSSError};

use crate::ppss::OPRFSession;
use prost::Message;
use rand::Rng;
use rand_core::CryptoRng;

use crate::proto::svr3;
use crate::proto::svr3::{create_response, evaluate_response};

const CONTEXT: &str = "Signal_SVR3_20231121_PPSS_Context";

pub struct Backup<'a> {
    oprfs: Vec<OPRFSession>,
    password: &'a str,
    secret: [u8; 32],
    server_ids: Vec<u64>,
    pub requests: Vec<Vec<u8>>,
}

impl<'a> Backup<'a> {
    pub fn new(
        server_ids: &[u64],
        password: &'a str,
        secret: [u8; 32],
        max_tries: u32,
    ) -> Result<Self, Error> {
        assert_ne!(0, max_tries);
        let oprfs = ppss::begin_oprfs(CONTEXT, server_ids, password)?;
        let requests = oprfs
            .iter()
            .map(|oprf| crate::make_create_request(max_tries, &oprf.blinded_elt_bytes))
            .map(|request| request.encode_to_vec())
            .collect();
        Ok(Self {
            oprfs,
            password,
            secret,
            server_ids: server_ids.into(),
            requests,
        })
    }

    pub fn finalize<R>(self, rng: &mut R, responses: &[Vec<u8>]) -> Result<MaskedShareSet, Error>
    where
        R: Rng + CryptoRng,
    {
        let evaluated_elements = responses
            .iter()
            .map(|vec| decode_create_response(vec))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = ppss::finalize_oprfs(self.oprfs, &evaluated_elements)?;
        Ok(ppss::backup_secret(
            CONTEXT,
            self.password.as_bytes(),
            self.server_ids,
            outputs,
            &self.secret,
            rng,
        ))
    }
}

pub struct Restore<'a> {
    oprfs: Vec<OPRFSession>,
    password: &'a str,
    share_set: MaskedShareSet,
    pub requests: Vec<Vec<u8>>,
}

impl<'a> Restore<'a> {
    pub fn new(password: &'a str, share_set: MaskedShareSet) -> Result<Self, Error> {
        let oprfs = ppss::begin_oprfs(CONTEXT, &share_set.server_ids, password)?;
        let requests = oprfs
            .iter()
            .map(|oprf| crate::make_evaluate_request(&oprf.blinded_elt_bytes))
            .map(|request| request.encode_to_vec())
            .collect();
        Ok(Self {
            oprfs,
            password,
            share_set,
            requests,
        })
    }
    pub fn finalize(self, responses: &[Vec<u8>]) -> Result<[u8; 32], Error> {
        let evaluated_elements = responses
            .iter()
            .map(|vec| decode_evaluate_response(vec))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = ppss::finalize_oprfs(self.oprfs, &evaluated_elements)?;
        let (secret, _key) =
            ppss::restore_secret(CONTEXT, self.password.as_bytes(), outputs, self.share_set)?;
        Ok(secret)
    }
}

fn make_create_request(max_tries: u32, blinded_element: &[u8]) -> svr3::Request {
    svr3::Request {
        inner: Some(svr3::request::Inner::Create(svr3::CreateRequest {
            max_tries,
            blinded_element: blinded_element.to_vec(),
        })),
    }
}

fn decode_create_response(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let decoded = svr3::Response::decode(bytes)?;
    if let Some(svr3::response::Inner::Create(response)) = decoded.inner {
        if response.status() == create_response::Status::Ok {
            Ok(response
                .evaluated_element
                .try_into()
                .expect("response should be of right size"))
        } else {
            let status_string = response.status().as_str_name();
            Err(Error::Protocol(format!(
                "Create response status: {status_string}"
            )))
        }
    } else {
        Err(Error::Protocol(
            "Unexpected or missing response".to_string(),
        ))
    }
}

fn make_evaluate_request(blinded_element: &[u8]) -> svr3::Request {
    svr3::Request {
        inner: Some(svr3::request::Inner::Evaluate(svr3::EvaluateRequest {
            blinded_element: blinded_element.to_vec(),
        })),
    }
}

fn decode_evaluate_response(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let decoded = svr3::Response::decode(bytes)?;
    if let Some(svr3::response::Inner::Evaluate(response)) = decoded.inner {
        if response.status() == evaluate_response::Status::Ok {
            Ok(response
                .evaluated_element
                .try_into()
                .expect("response should be of right size"))
        } else {
            let status_string = response.status().as_str_name();
            Err(Error::Protocol(format!(
                "Evaluate response status: {status_string}"
            )))
        }
    } else {
        Err(Error::Protocol(
            "Unexpected or missing response".to_string(),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::oprf::ciphersuite::hash_to_group;
    use crate::proto::svr3;
    use prost::Message;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use test_case::test_case;

    fn make_secret() -> [u8; 32] {
        let mut rng = OsRng;
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        secret
    }

    #[test]
    #[should_panic]
    fn zero_max_tries() {
        let _ = Backup::new(&[], "", [0; 32], 0);
    }

    #[test]
    fn backup_request_basic_checks() {
        let secret = make_secret();
        let backup = Backup::new(&[1, 2, 3], "password", secret, 1).expect("can create backup");
        assert_eq!(3, backup.requests.len());
        for request_bytes in backup.requests.into_iter() {
            let decode_result = svr3::Request::decode(&*request_bytes);
            assert!(matches!(
                decode_result,
                Ok(svr3::Request {
                    inner: Some(svr3::request::Inner::Create(svr3::CreateRequest {
                        max_tries: 1,
                        blinded_element,
                    })),
                    ..
                }) if !blinded_element.is_empty()
            ));
        }
    }

    fn make_create_response(status: svr3::create_response::Status) -> svr3::Response {
        let valid_evaluated_element = hash_to_group(&[0x0; 32]).compress().to_bytes().into();
        svr3::Response {
            inner: Some(svr3::response::Inner::Create(svr3::CreateResponse {
                status: status.into(),
                evaluated_element: valid_evaluated_element,
            })),
        }
    }

    #[test_case(svr3::create_response::Status::Unset, false ; "status_unset")]
    #[test_case(svr3::create_response::Status::Ok, true ; "status_ok")]
    #[test_case(svr3::create_response::Status::InvalidRequest, false ; "status_invalid_request")]
    #[test_case(svr3::create_response::Status::Error, false ; "status_error")]
    fn backup_finalize_checks_status(status: svr3::create_response::Status, should_succeed: bool) {
        let backup =
            Backup::new(&[1, 2, 3], "password", make_secret(), 1).expect("can create backup");
        let response = make_create_response(status).encode_to_vec();
        let mut rng = OsRng;
        let result = backup.finalize(&mut rng, &[response]);
        assert_eq!(should_succeed, result.is_ok());
    }

    #[test_case(vec![1, 2, 3]; "bad_protobuf")]
    #[test_case(make_evaluate_response(svr3::evaluate_response::Status::Ok).encode_to_vec(); "wrong_response_type")]
    fn backup_invalid_response(response: Vec<u8>) {
        let backup =
            Backup::new(&[1, 2, 3], "password", make_secret(), 1).expect("can create backup");
        let mut rng = OsRng;
        let result = backup.finalize(&mut rng, &[response]);
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    fn make_masked_share_set() -> MaskedShareSet {
        MaskedShareSet {
            server_ids: vec![1, 2, 3],
            masked_shares: vec![[0; 32], [1; 32], [2; 32]],
            commitment: [42; 32],
        }
    }

    #[test]
    fn restore_request_basic_checks() {
        let restore =
            Restore::new("password", make_masked_share_set()).expect("can create restore");
        assert_eq!(3, restore.requests.len());
        for request_bytes in restore.requests.into_iter() {
            let decode_result = svr3::Request::decode(&*request_bytes);
            assert!(matches!(
                decode_result,
                Ok(svr3::Request {
                    inner: Some(svr3::request::Inner::Evaluate(svr3::EvaluateRequest {
                        blinded_element,
                    })),
                    ..
                }) if !blinded_element.is_empty()
            ));
        }
    }

    fn make_evaluate_response(status: svr3::evaluate_response::Status) -> svr3::Response {
        let valid_evaluated_element = hash_to_group(&[0x0; 32]).compress().to_bytes().into();
        svr3::Response {
            inner: Some(svr3::response::Inner::Evaluate(svr3::EvaluateResponse {
                status: status.into(),
                evaluated_element: valid_evaluated_element,
                tries_remaining: 1,
            })),
        }
    }

    #[test_case(svr3::evaluate_response::Status::Unset, false; "status_unset")]
    #[test_case(svr3::evaluate_response::Status::Ok, true; "status_ok")]
    #[test_case(svr3::evaluate_response::Status::Missing, false; "status_missing")]
    #[test_case(svr3::evaluate_response::Status::InvalidRequest, false; "status_invalid_request")]
    #[test_case(svr3::evaluate_response::Status::Error, false; "status_error")]
    fn restore_finalize_checks_status(
        status: svr3::evaluate_response::Status,
        should_succeed: bool,
    ) {
        let restore = Restore::new("password", make_masked_share_set()).expect("can create backup");
        let response = make_evaluate_response(status).encode_to_vec();
        let result = restore.finalize(&[response]);
        let is_ppss_error = matches!(result, Err(Error::Ppss(ppss::PPSSError::InvalidCommitment)));
        assert_eq!(should_succeed, result.is_ok() || is_ppss_error);
    }

    #[test_case(vec![1, 2, 3]; "bad_protobuf")]
    #[test_case(make_create_response(svr3::create_response::Status::Ok).encode_to_vec(); "wrong_response_type")]
    fn restore_invalid_response(response: Vec<u8>) {
        let restore =
            Restore::new("password", make_masked_share_set()).expect("can create restore");
        let result = restore.finalize(&[response]);
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}
