//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::io::Write;
use std::num::NonZeroU32;

use prost::Message;
use rand_core::CryptoRngCore;

mod client;
mod oprf;
mod ppss;
pub use ppss::{MaskedShareSet, OPRFSession};

mod errors;
pub use errors::{Error, ErrorStatus, OPRFError, PPSSError};
mod proto;
use proto::svr3::{self, create_response, evaluate_response, query_response};
pub use proto::svr4::response4::Status as V4Status;

const SECRET_BYTES: usize = 32;
const CONTEXT: &str = "Signal_SVR3_20231121_PPSS_Context";

pub fn make_remove_request() -> Vec<u8> {
    svr3::Request {
        inner: Some(svr3::request::Inner::Remove(svr3::RemoveRequest {})),
    }
    .encode_to_vec()
}

pub struct Backup<'a> {
    oprfs: Vec<OPRFSession>,
    password: &'a str,
    secret: [u8; SECRET_BYTES],
    server_ids: Vec<u64>,
    pub requests: Vec<Vec<u8>>,
}

impl<'a> Backup<'a> {
    pub fn new<R: CryptoRngCore>(
        server_ids: &[u64],
        password: &'a str,
        secret: [u8; SECRET_BYTES],
        max_tries: NonZeroU32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let oprfs = ppss::begin_oprfs(CONTEXT, server_ids, password, rng)?;
        let requests = oprfs
            .iter()
            .map(|oprf| make_create_request(max_tries.into(), &oprf.blinded_elt_bytes))
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
        R: CryptoRngCore,
    {
        let evaluated_elements = responses
            .iter()
            .map(|vec| decode_create_response(vec))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = ppss::finalize_oprfs(self.oprfs, evaluated_elements)
            .map_err(|err| Error::Ppss(err, 0))?;
        Ok(ppss::backup_secret(
            CONTEXT,
            self.password.as_bytes(),
            self.server_ids,
            outputs,
            &self.secret,
            rng,
        )
        .expect("matching lengths of server_ids and outputs"))
    }
}

pub struct Restore<'a> {
    oprfs: Vec<OPRFSession>,
    password: &'a str,
    share_set: MaskedShareSet,
    pub requests: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EvaluationResult {
    pub value: [u8; SECRET_BYTES],
    pub tries_remaining: u32,
}

impl<'a> Restore<'a> {
    pub fn new<R: CryptoRngCore>(
        password: &'a str,
        share_set: MaskedShareSet,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let oprfs = ppss::begin_oprfs(CONTEXT, &share_set.server_ids, password, rng)?;
        let requests = oprfs
            .iter()
            .map(|oprf| make_evaluate_request(&oprf.blinded_elt_bytes))
            .map(|request| request.encode_to_vec())
            .collect();
        Ok(Self {
            oprfs,
            password,
            share_set,
            requests,
        })
    }

    /// Extracts the evaluation results from server responses.
    ///
    /// Panics if the `responses` slice is empty.
    pub fn finalize(self, responses: &[Vec<u8>]) -> Result<EvaluationResult, Error> {
        let evaluation_results = responses
            .iter()
            .map(|vec| decode_evaluate_response(vec))
            .collect::<Result<Vec<_>, _>>()?;
        let evaluated_elements = evaluation_results.iter().map(|r| r.value);
        // It is possible that different servers will have different idea of what the remaining tries value is.
        let tries_remaining = evaluation_results
            .iter()
            .map(|r| r.tries_remaining)
            .min()
            .expect("At least one server response expected");
        let outputs = ppss::finalize_oprfs(self.oprfs, evaluated_elements)
            .map_err(|err| Error::Ppss(err, tries_remaining))?;
        let (secret, _key) =
            ppss::restore_secret(CONTEXT, self.password.as_bytes(), outputs, self.share_set)
                .map_err(|err| Error::Ppss(err, tries_remaining))?;
        Ok(EvaluationResult {
            value: secret,
            tries_remaining,
        })
    }
}

pub enum Query {}

impl Query {
    // Using `impl Iterator<...>` makes libsignal-net fail to build in Rust 1.72
    pub fn requests() -> std::iter::Repeat<Vec<u8>> {
        std::iter::repeat(make_query_request().encode_to_vec())
    }

    /// Extracts the tries remaining value from server responses.
    ///
    /// Panics if the `responses` slice is empty.
    pub fn finalize(responses: &[Vec<u8>]) -> Result<u32, Error> {
        let results = responses
            .iter()
            .map(|vec| decode_query_response(vec))
            // Collecting into a vector is unnecessary wasteful but helps overall readability.
            .collect::<Result<Vec<_>, _>>()?;
        // It is possible that different servers will have different idea of what the remaining tries value is.
        let tries_remaining = results
            .into_iter()
            .min()
            .expect("At least one server response expected");
        Ok(tries_remaining)
    }
}

fn make_query_request() -> svr3::Request {
    svr3::Request {
        inner: Some(svr3::request::Inner::Query(svr3::QueryRequest {})),
    }
}

fn decode_query_response(bytes: &[u8]) -> Result<u32, Error> {
    let decoded = svr3::Response::decode(bytes)?;
    if let Some(svr3::response::Inner::Query(response)) = decoded.inner {
        if let Some(error_status) = ErrorStatus::from_query_status(response.status()) {
            Err(Error::BadResponseStatus(error_status))
        } else {
            Ok(response.tries_remaining)
        }
    } else {
        Err(Error::BadResponse)
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
        if let Some(error_status) = ErrorStatus::from_create_status(response.status()) {
            Err(Error::BadResponseStatus(error_status))
        } else {
            Ok(response
                .evaluated_element
                .try_into()
                .expect("response should be of right size"))
        }
    } else {
        Err(Error::BadResponse)
    }
}

fn make_evaluate_request(blinded_element: &[u8]) -> svr3::Request {
    svr3::Request {
        inner: Some(svr3::request::Inner::Evaluate(svr3::EvaluateRequest {
            blinded_element: blinded_element.to_vec(),
        })),
    }
}

impl From<svr3::EvaluateResponse> for EvaluationResult {
    fn from(response: svr3::EvaluateResponse) -> Self {
        Self {
            value: response
                .evaluated_element
                .try_into()
                .expect("response should be of right size"),
            tries_remaining: response.tries_remaining,
        }
    }
}

impl EvaluationResult {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<u32>() + SECRET_BYTES);
        bytes
            .write_all(&self.tries_remaining.to_be_bytes())
            .expect("can write to Vec");
        bytes.write_all(&self.value).expect("can write to Vec");
        bytes
    }
}

fn decode_evaluate_response(bytes: &[u8]) -> Result<EvaluationResult, Error> {
    let decoded = svr3::Response::decode(bytes)?;
    if let Some(svr3::response::Inner::Evaluate(response)) = decoded.inner {
        if let Some(error_status) = ErrorStatus::from_evaluate_status(response.status()) {
            Err(Error::BadResponseStatus(error_status))
        } else {
            Ok(response.into())
        }
    } else {
        Err(Error::BadResponse)
    }
}

impl ErrorStatus {
    fn from_query_status(status: query_response::Status) -> Option<Self> {
        match status {
            query_response::Status::Unset => Some(Self::Unset),
            query_response::Status::Ok => None,
            query_response::Status::Missing => Some(Self::Missing),
        }
    }

    fn from_create_status(status: create_response::Status) -> Option<Self> {
        match status {
            create_response::Status::Ok => None,
            create_response::Status::Unset => Some(Self::Unset),
            create_response::Status::InvalidRequest => Some(Self::InvalidRequest),
            create_response::Status::Error => Some(Self::Error),
        }
    }

    fn from_evaluate_status(status: evaluate_response::Status) -> Option<Self> {
        match status {
            evaluate_response::Status::Ok => None,
            evaluate_response::Status::Unset => Some(Self::Unset),
            evaluate_response::Status::Missing => Some(Self::Missing),
            evaluate_response::Status::InvalidRequest => Some(Self::InvalidRequest),
            evaluate_response::Status::Error => Some(Self::Error),
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use prost::Message;
    use rand_core::{OsRng, RngCore};
    use test_case::test_case;

    use oprf::ciphersuite::hash_to_group;
    use ppss::testutils::OPRFServerSet;
    use ppss::{backup_secret, begin_oprfs, finalize_oprfs};
    use proto::svr3;

    use super::*;

    // Not using [1, 2, 3] to prevent unfortunate accidental equalities.
    const SERVER_IDS: &[u64] = &[31, 41, 59];
    const PASSWORD: &str = "password";

    fn make_secret() -> [u8; SECRET_BYTES] {
        let mut rng = OsRng;
        let mut secret = [0; SECRET_BYTES];
        rng.fill_bytes(&mut secret);
        secret
    }

    #[test]
    fn backup_request_basic_checks() {
        let mut rng = OsRng;
        let secret = make_secret();
        let backup = Backup::new(SERVER_IDS, PASSWORD, secret, nonzero!(1u32), &mut rng)
            .expect("can create backup");
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
        let backup = Backup::new(
            SERVER_IDS,
            PASSWORD,
            make_secret(),
            nonzero!(1u32),
            &mut OsRng,
        )
        .expect("can create backup");
        let responses: Vec<_> = std::iter::repeat(make_create_response(status).encode_to_vec())
            .take(3)
            .collect();
        let mut rng = OsRng;
        let result = backup.finalize(&mut rng, &responses);
        assert_eq!(should_succeed, result.is_ok());
    }

    #[test_case(vec![1, 2, 3], Error::BadData; "bad_protobuf")]
    #[test_case(
        make_evaluate_response(svr3::evaluate_response::Status::Ok).encode_to_vec(),
        Error::BadResponse;
        "wrong_response_type")]
    fn backup_invalid_response(response: Vec<u8>, _expected: Error) {
        let backup = Backup::new(&[1], PASSWORD, make_secret(), nonzero!(1u32), &mut OsRng)
            .expect("can create backup");
        let mut rng = OsRng;
        let result = backup.finalize(&mut rng, &[response]);
        assert_matches!(result, Err(_expected));
    }

    fn make_masked_share_set() -> MaskedShareSet {
        let mut rng = OsRng;

        let oprf_servers = OPRFServerSet::new(SERVER_IDS);
        let oprfs = begin_oprfs(CONTEXT, SERVER_IDS, PASSWORD, &mut rng).unwrap();

        let eval_elt_bytes: Vec<[u8; 32]> = oprfs
            .iter()
            .map(|oprf| oprf_servers.eval(&oprf.server_id, &oprf.blinded_elt_bytes))
            .collect();

        let outputs = finalize_oprfs(oprfs, eval_elt_bytes).unwrap();
        backup_secret(
            CONTEXT,
            PASSWORD.as_bytes(),
            SERVER_IDS.to_vec(),
            outputs,
            &make_secret(),
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn restore_request_basic_checks() {
        let restore = Restore::new(PASSWORD, make_masked_share_set(), &mut OsRng)
            .expect("can create restore");
        assert_eq!(3, restore.requests.len());
        for request_bytes in restore.requests.into_iter() {
            let decode_result = svr3::Request::decode(&*request_bytes);
            assert_matches!(
                decode_result,
                Ok(svr3::Request {
                    inner: Some(svr3::request::Inner::Evaluate(svr3::EvaluateRequest {
                        blinded_element,
                    })),
                    ..
                }) if !blinded_element.is_empty()
            );
        }
    }

    fn make_evaluate_response(status: evaluate_response::Status) -> svr3::Response {
        let valid_evaluated_element = hash_to_group(&[0x0; 32]).compress().to_bytes().into();
        svr3::Response {
            inner: Some(svr3::response::Inner::Evaluate(svr3::EvaluateResponse {
                status: status.into(),
                evaluated_element: valid_evaluated_element,
                tries_remaining: 1,
            })),
        }
    }

    fn make_valid_evaluate_responses(restore: &Restore) -> Vec<svr3::Response> {
        let oprf_servers = OPRFServerSet::new(SERVER_IDS);

        restore
            .oprfs
            .iter()
            .map(|oprf| {
                let bytes = oprf_servers.eval(&oprf.server_id, &oprf.blinded_elt_bytes);
                svr3::Response {
                    inner: Some(svr3::response::Inner::Evaluate(svr3::EvaluateResponse {
                        status: evaluate_response::Status::Ok.into(),
                        evaluated_element: bytes.to_vec(),
                        tries_remaining: oprf
                            .server_id
                            .try_into()
                            .expect("server id does not fit into u32"),
                    })),
                }
            })
            .collect()
    }

    fn make_query_response(status: query_response::Status, tries_remaining: u32) -> svr3::Response {
        svr3::Response {
            inner: Some(svr3::response::Inner::Query(svr3::QueryResponse {
                status: status.into(),
                tries_remaining,
            })),
        }
    }

    #[test_case(svr3::evaluate_response::Status::Unset; "status_unset")]
    #[test_case(svr3::evaluate_response::Status::Missing; "status_missing")]
    #[test_case(svr3::evaluate_response::Status::InvalidRequest; "status_invalid_request")]
    #[test_case(svr3::evaluate_response::Status::Error; "status_error")]
    fn restore_finalize_checks_status_error(status: svr3::evaluate_response::Status) {
        let share_set = make_masked_share_set();
        let restore = Restore::new(PASSWORD, share_set, &mut OsRng).expect("can create backup");
        let responses: Vec<_> = std::iter::repeat(make_evaluate_response(status).encode_to_vec())
            .take(3)
            .collect();
        let result = restore.finalize(&responses);
        assert_matches!(result, Err(Error::BadResponseStatus(actual_status)) =>
            assert_eq!(ErrorStatus::from_evaluate_status(status), Some(actual_status)));
    }

    #[test]
    fn restore_finalize_returns_minimum_tries() {
        let restore =
            Restore::new(PASSWORD, make_masked_share_set(), &mut OsRng).expect("can create backup");
        let responses: Vec<_> = make_valid_evaluate_responses(&restore)
            .into_iter()
            .map(|r| r.encode_to_vec())
            .collect();
        let result = restore.finalize(&responses);
        assert_matches!(
            result,
            Ok(EvaluationResult {
                tries_remaining: 31,
                ..
            })
        );
    }

    #[test_case(vec![1, 2, 3], Error::BadData; "bad_protobuf")]
    #[test_case(
        make_create_response(svr3::create_response::Status::Ok).encode_to_vec(),
        Error::BadResponse;
        "wrong_response_type")]
    fn restore_invalid_response(response: Vec<u8>, _expected: Error) {
        let restore = Restore::new(PASSWORD, make_masked_share_set(), &mut OsRng)
            .expect("can create restore");
        let result = restore.finalize(&[response]);
        assert_matches!(result, Err(_expected));
    }

    #[test]
    #[should_panic]
    fn restore_finalize_panics_with_no_responses() {
        if let Ok(restore) = Restore::new(PASSWORD, make_masked_share_set(), &mut OsRng) {
            let _ = restore.finalize(&[]);
        }
    }

    #[test_case(query_response::Status::Unset; "status_unset")]
    #[test_case(query_response::Status::Missing; "status_missing")]
    fn query_finalize_checks_status_error(status: query_response::Status) {
        let responses = [make_query_response(status, 42).encode_to_vec()];
        let result = Query::finalize(&responses);
        assert_matches!(result, Err(Error::BadResponseStatus(actual_status)) =>
            assert_eq!(ErrorStatus::from_query_status(status), Some(actual_status)));
    }

    #[test]
    fn query_returns_minimum_tries() {
        let responses: Vec<_> = [4u32, 3, 42]
            .into_iter()
            .map(|tries| make_query_response(query_response::Status::Ok, tries).encode_to_vec())
            .collect();

        let result = Query::finalize(&responses);
        assert_matches!(result, Ok(3));
    }

    #[test]
    #[should_panic]
    fn query_finalize_panics_with_no_responses() {
        let _ = Query::finalize(&[]);
    }
}
