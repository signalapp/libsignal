//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::{max, min};
use std::io;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bitstream_io::{
    BigEndian, BitRead, BitReader, BitWrite, BitWriter, ByteRead, ByteReader, ByteWrite, ByteWriter,
};
use tokio::time::Instant;

use crate::dns::dns_types::Expiring;
use crate::dns::ResourceType;

pub(crate) const QCLASS_IN: u16 = 1;
const POINTER_MASK: u8 = 0xC0;

// Size limits introduced by the specification:
// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
pub(crate) const MAX_DNS_LABEL_LEN: usize = 63;
pub(crate) const MAX_DNS_NAME_LEN: usize = 255;
pub(crate) const MAX_DNS_UDP_MESSAGE_LEN: usize = 512;

#[derive(displaydoc::Display, Debug, thiserror::Error, Clone)]
pub enum Error {
    /// Invalid domain name (a label is longer than {MAX_DNS_LABEL_LEN:?} octets)
    ProtocolErrorLabelTooLong,
    /// Invalid domain name (empty label)
    ProtocolErrorLabelEmpty,
    /// Invalid domain name (longer than {MAX_DNS_NAME_LEN:?} octets)
    ProtocolErrorNameTooLong,
    /// Value of a message field is not expected
    ProtocolErrorUnexpectedValue,
    /// Failed to parse a DNS message according to the protocol expectations
    ProtocolErrorInvalidMessage,
    /// Failed to decode name from the DNS response
    ProtocolErrorInvalidNameCharacters,
    /// Failed to parse resourse record
    ProtocolErrorFailedToParseResourceRecord,
    /// Data for the given name is not available
    NoData,
    /// DNS request resulted in a non-zero error code: {0}
    RequestFailedWithErrorCode(u8),
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::ProtocolErrorInvalidMessage
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Creates a DNS request for the given request id, domain name, and resource type.
///
/// In this simple case, we only have one question and it's always recursive.
/// This way, a big portion of the message is filled with a predefined data.
///
/// [Header section](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1)
/// [Question section](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2)
/// [UDP usage](https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1)
/// [TCP usage](https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
pub fn create_request_with_id(
    request_id: u16,
    domain: &str,
    resource_type: ResourceType,
) -> Result<Vec<u8>> {
    // the information hardcoded in this section is that the message is a request
    // and that the request is recursive
    const RECURSIVE_REQUEST_WITH_ONE_QUESTION: [u8; 10] = [1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    //
    const MESSAGE_BOILERPLATE_SIZE: usize = 18;

    let mut writer = BitWriter::endian(
        Vec::with_capacity(MESSAGE_BOILERPLATE_SIZE + max(domain.len(), MAX_DNS_NAME_LEN)),
        BigEndian,
    );

    // Header section

    // request ID
    writer.write_from(request_id)?;
    // the rest of the header
    writer.write_bytes(RECURSIVE_REQUEST_WITH_ONE_QUESTION.as_slice())?;

    // Question section

    // name
    write_name(&mut writer.bytewriter().expect("byte aligned"), domain)?;
    // the rest of the request
    writer.write_from(resource_type as u16)?;
    writer.write_from(QCLASS_IN)?;

    Ok(writer.into_writer())
}

pub fn get_id(message: &[u8]) -> Result<u16> {
    match message {
        [a, b, ..] => Ok(((*a as u16) << 8) | *b as u16),
        _ => Err(Error::ProtocolErrorInvalidMessage),
    }
}

pub fn parse_a_record(bytes_vec: &[u8]) -> Result<Ipv4Addr> {
    let octets: [u8; 4] = bytes_vec
        .try_into()
        .map_err(|_| Error::ProtocolErrorFailedToParseResourceRecord)?;
    Ok(Ipv4Addr::from(octets))
}

pub fn parse_aaaa_record(bytes_vec: &[u8]) -> Result<Ipv6Addr> {
    let octets: [u8; 16] = bytes_vec
        .try_into()
        .map_err(|_| Error::ProtocolErrorFailedToParseResourceRecord)?;
    Ok(Ipv6Addr::from(octets))
}

pub fn parse_response<T>(
    message: &[u8],
    expected_type: ResourceType,
    parser: fn(&[u8]) -> Result<T>,
) -> Result<Expiring<Vec<T>>> {
    let mut reader = BitReader::endian(Cursor::new(message), BigEndian);

    let _id = reader.read_to::<u16>()?;
    let _flag_is_response = reader.read_bit()?;
    let _flag_operation_code = reader.read::<u8>(4)?;
    let _flag_authoritative_answer = reader.read_bit()?;
    let _flag_truncated = reader.read_bit()?;
    let _flag_recursion_requested = reader.read_bit()?;
    let _flag_recursion_available = reader.read_bit()?;
    let _flag_zero = reader.read::<u8>(3)?;
    let response_code = reader.read::<u8>(4)?;
    let _questions_count = reader.read_to::<u16>()?;
    let answers_count = reader.read_to::<u16>()?;
    let _authority_record_count = reader.read_to::<u16>()?;
    let _additional_record_count = reader.read_to::<u16>()?;

    if response_code != 0 {
        return Err(Error::RequestFailedWithErrorCode(response_code));
    }
    if answers_count == 0 {
        return Err(Error::NoData);
    }

    // question section repeats here
    let _name = read_name(&mut reader, message)?;
    let _data_type = reader.read_to::<u16>()?;
    let _data_class = reader.read_to::<u16>()?;

    let mut results = Vec::with_capacity(answers_count.into());
    let mut min_ttl = u32::MAX;
    for _ in 0..answers_count {
        let _name = read_name(&mut reader, message)?;
        let data_type = reader.read_to::<u16>()?;
        let _data_class = reader.read_to::<u16>()?;
        let data_ttl = reader.read_to::<u32>()?;
        let data_length = reader.read_to::<u16>()?;

        let data = reader.read_to_vec(data_length as usize)?;
        let expected_type = expected_type as u16;
        if data_type != expected_type {
            log::debug!(
                "expected resource records of type {} but have {}",
                expected_type,
                data_type
            );
            continue;
        }
        match parser(data.as_slice()) {
            Ok(data) => results.push(data),
            Err(error) => log::warn!("error parsing DNS response: {}", error),
        }

        min_ttl = min(min_ttl, data_ttl);
    }
    Ok(Expiring {
        data: results,
        expiration: Instant::now() + Duration::from_secs(min_ttl.into()),
    })
}

fn write_name<W: io::Write>(writer: &mut ByteWriter<W, BigEndian>, name: &str) -> Result<()> {
    let no_trailing_dot = name.strip_suffix('.').unwrap_or(name);

    // still need to account for a trailing empty label when checking the size
    if no_trailing_dot.len() + 1 >= MAX_DNS_NAME_LEN {
        return Err(Error::ProtocolErrorNameTooLong);
    }
    let labels = no_trailing_dot.split('.');
    for s in labels {
        let label_len: u8 = match s.len() {
            0 => return Err(Error::ProtocolErrorLabelEmpty),
            l if l > MAX_DNS_LABEL_LEN => return Err(Error::ProtocolErrorLabelTooLong),
            l => l.try_into().expect("value in u8 range"),
        };
        writer.write(label_len)?;
        writer.write_bytes(s.as_bytes())?;
    }
    writer.write(0u8)?;
    Ok(())
}

fn read_name<R: io::Read + io::Seek>(
    reader: &mut BitReader<R, BigEndian>,
    src: &[u8],
) -> Result<String> {
    let mut dst = vec![];
    let bytes_read: usize = (reader.position_in_bits()? / 8)
        .try_into()
        .expect("in usize range");
    let mut reader = reader.bytereader().expect("byte aligned");
    // passing a slice of the source message
    // that only contains bytes that has already been seen
    read_name_to_vec(&mut reader, &src[..bytes_read], &mut dst)?;
    String::from_utf8(dst).map_err(|_| Error::ProtocolErrorInvalidNameCharacters)
}

/// Parsing message according to the name serialization and compression rules.
///
/// This method is reading bytes appending them to the provided vector.
/// The name itself can then be constructed by creating a String out of the bytes.
///
/// [Name format](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2)
/// [Message Compression](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)
fn read_name_to_vec<R: io::Read>(
    reader: &mut ByteReader<R, BigEndian>,
    preceding_bytes: &[u8],
    dst: &mut Vec<u8>,
) -> Result<()> {
    let mut buf: [u8; u8::MAX as usize] = [0; u8::MAX as usize];
    loop {
        let label_len = reader.read::<u8>()?;
        if label_len == 0 {
            return Ok(());
        }
        if label_len & POINTER_MASK == POINTER_MASK {
            let byte2 = reader.read::<u8>()? as u16;
            let byte1 = (label_len & !POINTER_MASK) as u16;
            let offset = ((byte1 << 8) | byte2) as usize;
            // offset can only be referring to a preceding location
            if offset >= preceding_bytes.len() {
                return Err(Error::ProtocolErrorInvalidMessage);
            }
            // every time we make a recursive call,
            // we're shrinking the slice of `preceding_bytes`
            // so that recursion will eventually stop
            return read_name_to_vec(
                &mut ByteReader::endian(Cursor::new(&preceding_bytes[offset..]), BigEndian),
                &preceding_bytes[..offset],
                dst,
            );
        }
        if !dst.is_empty() {
            dst.push(b'.');
        }
        let label_len = label_len as usize;
        reader.read_bytes(&mut buf[..label_len])?;
        dst.extend_from_slice(&buf[..label_len]);
    }
}

#[cfg(test)]
mod test {
    use std::iter;
    use std::str::FromStr;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use const_str::{concat_bytes, ip_addr};
    use hickory_proto::op::{MessageType, ResponseCode};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use itertools::Itertools;
    use tokio::time::Instant;

    use super::*;
    use crate::dns::dns_types::ResourceType;

    const REQUEST_ID: u16 = 0xABCD;
    const VALID_DOMAIN: &str = "chat.signal.org";

    #[test]
    fn valid_requests_identical() {
        // build a query using a 3rd-party crate
        let mut header = hickory_proto::op::Header::new();
        header
            .set_message_type(MessageType::Query)
            .set_id(REQUEST_ID)
            .set_recursion_desired(true);
        let mut query = hickory_proto::op::Query::new();
        query
            .set_name(Name::from_str(VALID_DOMAIN).expect("valid name"))
            .set_query_type(RecordType::A);
        let mut hickory_message = hickory_proto::op::message::Message::new();
        hickory_message.set_header(header).add_query(query);
        let hickory_message = hickory_message.to_bytes().expect("valid message");

        // build our own query
        let query = create_request_with_id(REQUEST_ID, VALID_DOMAIN, ResourceType::A)
            .expect("valid request");

        assert_eq!(hickory_message, query);
    }

    #[test]
    fn request_allows_dot_at_the_end() {
        // build our own query
        let query1 = create_request_with_id(REQUEST_ID, VALID_DOMAIN, ResourceType::A)
            .expect("valid request");

        let with_dot = format!("{}.", VALID_DOMAIN);
        let query2 =
            create_request_with_id(REQUEST_ID, &with_dot, ResourceType::A).expect("valid request");

        assert_eq!(query1, query2);
    }

    #[test]
    fn invalid_name_too_long() {
        // 127 labels produces a domain name of length 254,
        // which, with a '.' suffix, is exactly the maximum allowed name length
        let mut long_name = iter::repeat('a').take(127).join(".");
        assert_matches!(
            create_request_with_id(REQUEST_ID, &long_name, ResourceType::A),
            Ok(_)
        );
        // with one more character the name becomes too long
        long_name.push('a');
        assert_matches!(
            create_request_with_id(REQUEST_ID, &long_name, ResourceType::A),
            Err(Error::ProtocolErrorNameTooLong)
        );
    }

    #[test]
    fn invalid_name_empty_label() {
        for name in ["", ".", "chat..signal.org", ".chat.signal.org"] {
            assert_matches!(
                create_request_with_id(REQUEST_ID, name, ResourceType::A),
                Err(Error::ProtocolErrorLabelEmpty)
            );
        }
    }

    #[test]
    fn invalid_name_label_too_long() {
        let mut long_label = iter::repeat('a').take(MAX_DNS_LABEL_LEN).join("");
        let name = format!("{}.signal.org", long_label);
        assert_matches!(
            create_request_with_id(REQUEST_ID, &name, ResourceType::A),
            Ok(_)
        );

        long_label.push('a');
        let name = format!("{}.signal.org", long_label);
        assert_matches!(
            create_request_with_id(REQUEST_ID, &name, ResourceType::A),
            Err(Error::ProtocolErrorLabelTooLong)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn valid_response_parsed_correctly() {
        let shorter_ttl = Duration::from_secs(1);
        let longer_ttl = Duration::from_secs(2);
        let expected_ips_and_ttls = [
            (ip_addr!(v4, "1.1.1.1"), longer_ttl),
            (ip_addr!(v4, "1.1.1.2"), shorter_ttl),
        ];
        let name = Name::from_str(VALID_DOMAIN).expect("valid name");

        let response_message = response_bytes(RecordType::A, |message| {
            for ip_and_ttl in expected_ips_and_ttls {
                let (ip, ttl) = ip_and_ttl;
                let mut rr = hickory_proto::rr::Record::<RData>::new();
                rr.set_name(name.clone())
                    .set_record_type(RecordType::A)
                    .set_ttl(ttl.as_secs().try_into().unwrap())
                    .set_data(Some(RData::A(A::from(ip))));
                message.add_answer(rr);
            }
        });

        // parsing response message
        let response = parse_response(response_message.as_slice(), ResourceType::A, parse_a_record)
            .expect("parsed result");

        assert_matches!(get_id(response_message.as_slice()), Ok(REQUEST_ID));
        assert_eq!(
            &expected_ips_and_ttls.map(|p| p.0),
            response.data.as_slice()
        );
        assert_eq!(Instant::now() + shorter_ttl, response.expiration);
    }

    #[test]
    fn invalid_message_error_parsing_id() {
        assert_matches!(get_id(&[]), Err(Error::ProtocolErrorInvalidMessage));
        assert_matches!(get_id(&[0]), Err(Error::ProtocolErrorInvalidMessage));
    }

    #[test]
    fn invalid_message_error_parsing_data() {
        assert_matches!(
            parse_response(&[], ResourceType::A, |_| Ok(())),
            Err(Error::ProtocolErrorInvalidMessage)
        );
    }

    #[test]
    fn compressed_name_format_handled_correctly() {
        let expected = "signal.org";
        // valid pointer case
        let src = concat_bytes!(6, b"signal", 3, b"org", 0, POINTER_MASK, 0);
        let mut reader = ByteReader::endian(Cursor::new(&src), BigEndian);
        // reading uncompressed entry
        let mut dst = vec![];
        read_name_to_vec(&mut reader, &src[..0], &mut dst).unwrap();
        let result = String::from_utf8(dst).expect("valid string");
        assert_eq!(expected, result);

        // reading compressed entry
        let mut dst = vec![];
        read_name_to_vec(&mut reader, &src[..(expected.len() + 2)], &mut dst).unwrap();
        let result = String::from_utf8(dst).expect("valid string");
        assert_eq!(expected, result);
    }

    #[test]
    fn compressed_name_format_handles_errors() {
        let expected = "signal.org";
        // invalid pointer case
        let src = concat_bytes!(6, b"signal", 3, b"org", 0, POINTER_MASK, 20);
        let mut reader = ByteReader::endian(Cursor::new(&src), BigEndian);
        // reading uncompressed entry
        let mut dst = vec![];
        read_name_to_vec(&mut reader, &src[..0], &mut dst).unwrap();
        let result = String::from_utf8(dst).expect("valid string");
        assert_eq!(expected, result);

        // reading compressed entry
        let mut dst = vec![];
        assert_matches!(
            read_name_to_vec(&mut reader, &src[..(expected.len() + 2)], &mut dst),
            Err(Error::ProtocolErrorInvalidMessage)
        );
    }

    #[test]
    fn error_response_code_handled_correctly() {
        let expected_response_code = 2;
        let response_message = response_bytes(RecordType::A, |message| {
            message.set_response_code(ResponseCode::from_low(expected_response_code));
        });

        // parsing response message
        let response = parse_response(response_message.as_slice(), ResourceType::A, |_| Ok(()));

        assert_matches!(
            response,
            Err(Error::RequestFailedWithErrorCode(c)) if c == expected_response_code
        )
    }

    #[test]
    fn response_with_no_answers_handled_correctly() {
        let response_message = response_bytes(RecordType::A, |_| {});

        // parsing response message
        let response = parse_response(response_message.as_slice(), ResourceType::A, |_| Ok(()));

        assert_matches!(response, Err(Error::NoData))
    }

    #[test]
    fn unexpected_resource_record_is_skipped() {
        let ttl_sec = 100;
        let name = Name::from_str(VALID_DOMAIN).expect("valid name");
        let expected_ip = ip_addr!(v4, "1.1.1.1");
        let response_message = response_bytes(RecordType::A, |message| {
            // add CNAME record
            let cname = Name::from_str("cname.signal.org").unwrap();
            let mut rr = hickory_proto::rr::Record::<RData>::new();
            rr.set_name(name.clone())
                .set_record_type(RecordType::CNAME)
                .set_ttl(ttl_sec)
                .set_data(Some(RData::CNAME(CNAME(cname))));
            message.add_answer(rr);

            // add A record
            let mut rr = hickory_proto::rr::Record::<RData>::new();
            rr.set_name(name.clone())
                .set_record_type(RecordType::A)
                .set_ttl(ttl_sec)
                .set_data(Some(RData::A(A::from(expected_ip))));
            message.add_answer(rr);
        });

        // parsing response message
        let response = parse_response(response_message.as_slice(), ResourceType::A, parse_a_record)
            .expect("parsed result");

        assert_matches!(get_id(response_message.as_slice()), Ok(REQUEST_ID));
        assert_eq!(&[expected_ip], response.data.as_slice());
    }

    #[test]
    fn record_with_invalid_data_is_skipped() {
        const EXPECTED_IP: Ipv4Addr = ip_addr!(v4, "1.1.1.1");
        let ttl_sec = 100;
        let name = Name::from_str(VALID_DOMAIN).expect("valid name");
        let ip_to_simulate_error = ip_addr!(v4, "2.2.2.2");
        let response_message = response_bytes(RecordType::A, move |message| {
            // add invalid record
            let mut rr = hickory_proto::rr::Record::<RData>::new();
            rr.set_name(name.clone())
                .set_record_type(RecordType::A)
                .set_ttl(ttl_sec)
                .set_data(Some(RData::A(A::from(ip_to_simulate_error))));
            message.add_answer(rr);

            // add A record
            let mut rr = hickory_proto::rr::Record::<RData>::new();
            rr.set_name(name.clone())
                .set_record_type(RecordType::A)
                .set_ttl(ttl_sec)
                .set_data(Some(RData::A(A::from(EXPECTED_IP))));
            message.add_answer(rr);
        });

        // parsing response message
        let response = parse_response(
            response_message.as_slice(),
            ResourceType::A,
            move |bytes_vec| {
                let octets: [u8; 4] = bytes_vec
                    .try_into()
                    .map_err(|_| Error::ProtocolErrorFailedToParseResourceRecord)?;
                let res = Ipv4Addr::from(octets);
                if res == EXPECTED_IP {
                    Ok(res)
                } else {
                    Err(Error::ProtocolErrorInvalidMessage)
                }
            },
        )
        .expect("parsed result");

        assert_matches!(get_id(response_message.as_slice()), Ok(REQUEST_ID));
        assert_eq!(&[EXPECTED_IP], response.data.as_slice());
    }

    fn response_bytes<F>(record_type: RecordType, builder: F) -> Vec<u8>
    where
        F: FnOnce(&mut hickory_proto::op::message::Message),
    {
        let mut header = hickory_proto::op::Header::new();
        header
            .set_message_type(MessageType::Response)
            .set_id(REQUEST_ID)
            .set_recursion_desired(true);

        let name = Name::from_str(VALID_DOMAIN).expect("valid name");
        let mut query = hickory_proto::op::Query::new();
        query.set_name(name.clone()).set_query_type(record_type);

        let mut hickory_message = hickory_proto::op::message::Message::new();
        hickory_message.set_header(header).add_query(query);

        builder(&mut hickory_message);

        hickory_message.to_bytes().unwrap()
    }
}
