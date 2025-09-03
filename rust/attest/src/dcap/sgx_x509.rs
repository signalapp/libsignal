//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use asn1::{ObjectIdentifier, SequenceOf, oid};
use boring_signal::asn1::Asn1ObjectRef;
use boring_signal::nid::Nid;

use crate::dcap::{Error, Result};
use crate::error::Context;

pub const SGX_EXTENSIONS_OID: &str = "1.2.840.113741.1.13.1";
const _SGX_EXTENSIONS_OID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1);
const PPID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 1);

const TCB_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2);
const TCB_COMP01SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 1);
const TCB_COMP02SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 2);
const TCB_COMP03SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 3);
const TCB_COMP04SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 4);
const TCB_COMP05SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 5);
const TCB_COMP06SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 6);
const TCB_COMP07SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 7);
const TCB_COMP08SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 8);
const TCB_COMP09SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 9);
const TCB_COMP10SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 10);
const TCB_COMP11SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 11);
const TCB_COMP12SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 12);
const TCB_COMP13SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 13);
const TCB_COMP14SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 14);
const TCB_COMP15SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 15);
const TCB_COMP16SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 16);
const TCB_PCESVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 17);
const TCB_CPUSVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 18);

const PCE_ID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 3);
const FMSPC_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 4);
const SGX_TYPE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 5);
const PLATFORM_INSTANCE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 6);

const CONFIGURATION_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7);
const CONFIGURATION_DYNAMIC_PLATFORM_OID: ObjectIdentifier =
    oid!(1, 2, 840, 113741, 1, 13, 1, 7, 1);
const CONFIGURATION_CACHED_KEYS_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 2);
const CONFIGURATION_SMT_ENABLED_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 3);

const PPID_LEN: usize = 16;
const CPUSVN_LEN: usize = 16;
const PCEID_LEN: usize = 2;
const FMSPC_LEN: usize = 6;
const PLATFORM_INSTANCE_ID_LEN: usize = 16;
const COMPSVN_LEN: usize = 16;

#[derive(Debug)]
pub(crate) struct SgxPckExtension {
    // intel-dcap returns ppid, sgx_type, platform_instance_id,
    // configuration as supplemental data, but doesn't check any of them
    _ppid: [u8; PPID_LEN],
    pub tcb: Tcb,
    pub pceid: [u8; PCEID_LEN],
    pub fmspc: [u8; FMSPC_LEN],
    _sgx_type: SgxType,
    _platform_instance_id: [u8; PLATFORM_INSTANCE_ID_LEN],
    _configuration: Configuration,
}

impl SgxPckExtension {
    /// Whether the `asn_object` a top-level SgxPckExtension
    pub fn is_pck_ext(asn_object: &Asn1ObjectRef) -> bool {
        // check for SGX custom oid
        asn_object.nid() == Nid::UNDEF && asn_object.oid_string() == SGX_EXTENSIONS_OID
    }

    pub fn from_der(der: &[u8]) -> Result<SgxPckExtension> {
        let mut ppid = None;
        let mut tcb = None;
        let mut pceid = None;
        let mut fmspc = None;
        let mut sgx_type = None;
        let mut platform_instance_id = None;
        let mut configuration = None;

        let extensions = asn1::parse_single::<asn1::SequenceOf<SgxExtension>>(der)
            .map_err(|_| Error::new("could not parse required extension from PCK certificate"))?;

        parse_extensions(
            extensions,
            HashMap::from([
                (
                    PPID_OID,
                    &mut ppid as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (TCB_OID, &mut tcb),
                (PCE_ID_OID, &mut pceid),
                (FMSPC_OID, &mut fmspc),
                (SGX_TYPE_OID, &mut sgx_type),
                (PLATFORM_INSTANCE_OID, &mut platform_instance_id),
                (CONFIGURATION_OID, &mut configuration),
            ]),
        )?;

        Ok(SgxPckExtension {
            _ppid: ppid.unwrap(),
            tcb: tcb.unwrap(),
            pceid: pceid.unwrap(),
            fmspc: fmspc.unwrap(),
            _sgx_type: sgx_type.unwrap(),
            _platform_instance_id: platform_instance_id.unwrap(),
            _configuration: configuration.unwrap(),
        })
    }
}

#[derive(asn1::Asn1Read)]
struct SgxExtension<'a> {
    pub sgx_extension_id: ObjectIdentifier,
    pub value: ExtensionValue<'a>,
}

#[derive(asn1::Asn1Read)]
enum ExtensionValue<'a> {
    OctetString(&'a [u8]),
    Sequence(SequenceOf<'a, SgxExtension<'a>>),
    Integer(u64),
    Enumerated(asn1::Enumerated),
    Bool(bool),
}

impl<'a, const LEN: usize> TryFrom<ExtensionValue<'a>> for [u8; LEN] {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::OctetString(v) = value {
            v.try_into()
                .map_err(|_| Error::new("malformed extension value in PCK certificate"))
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u8 {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Integer(v) = value {
            v.try_into()
                .map_err(|_| Error::new("malformed extension value in PCK certificate"))
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u16 {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Integer(v) = value {
            v.try_into()
                .map_err(|_| Error::new("malformed extension value in PCK certificate"))
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}
impl<'a> TryFrom<ExtensionValue<'a>> for bool {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Bool(v) = value {
            Ok(v)
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

fn parse_extensions<'a>(
    extensions: asn1::SequenceOf<'a, SgxExtension<'a>>,
    mut attributes: HashMap<ObjectIdentifier, &mut dyn OptionOfTryFromExtensionValue>,
) -> Result<()> {
    for extension in extensions {
        let SgxExtension {
            sgx_extension_id,
            value,
        } = extension;
        if let Some(attr) = attributes.get_mut(&sgx_extension_id) {
            attr.parse_and_save(value)
                .with_context(|| sgx_extension_id.to_string())?;
        } else {
            return Err(Error::new(format!(
                "unexpected extension in PCK certificate {sgx_extension_id}"
            )));
        }
    }
    for (oid, attr) in attributes {
        if attr.is_none() {
            return Err(Error::new(format!(
                "could not parse required extension from PCK certificate: {oid}"
            )));
        }
    }
    Ok(())
}

/// Exists because `&mut Option<dyn TryFrom<…>>` isn't a thing in Rust.
///
/// (If you're wondering how it would work, read Gankra's
/// "[DSTs Are Just Polymorphically Compiled Generics][dsts]".)
///
/// [dsts]: https://gankra.github.io/blah/dsts-are-polymorphic-generics/
trait OptionOfTryFromExtensionValue {
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<()>;
    fn is_none(&self) -> bool;
}

impl<T> OptionOfTryFromExtensionValue for Option<T>
where
    T: for<'a> TryFrom<ExtensionValue<'a>, Error = Error>,
{
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<()> {
        if self.is_some() {
            return Err(Error::new("duplicate extension in PCK certificate"));
        }
        *self = Some(T::try_from(value)?);
        Ok(())
    }

    fn is_none(&self) -> bool {
        self.is_none()
    }
}

#[derive(Debug)]
pub(crate) struct Tcb {
    pub compsvn: [u8; COMPSVN_LEN],
    pub pcesvn: u16,
    _cpusvn: [u8; CPUSVN_LEN],
}

impl<'a> TryFrom<ExtensionValue<'a>> for Tcb {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Sequence(v) = value {
            Self::try_from(v)
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Tcb {
    type Error = Error;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self> {
        let mut compsvn = [None; COMPSVN_LEN];
        let mut pcesvn = None;
        let mut cpusvn = None;

        let oid_to_compsvn = [
            TCB_COMP01SVN_OID,
            TCB_COMP02SVN_OID,
            TCB_COMP03SVN_OID,
            TCB_COMP04SVN_OID,
            TCB_COMP05SVN_OID,
            TCB_COMP06SVN_OID,
            TCB_COMP07SVN_OID,
            TCB_COMP08SVN_OID,
            TCB_COMP09SVN_OID,
            TCB_COMP10SVN_OID,
            TCB_COMP11SVN_OID,
            TCB_COMP12SVN_OID,
            TCB_COMP13SVN_OID,
            TCB_COMP14SVN_OID,
            TCB_COMP15SVN_OID,
            TCB_COMP16SVN_OID,
        ]
        .into_iter()
        .zip(
            compsvn
                .iter_mut()
                .map(|v| v as &mut dyn OptionOfTryFromExtensionValue),
        )
        .chain([
            (
                TCB_PCESVN_OID,
                &mut pcesvn as &mut dyn OptionOfTryFromExtensionValue,
            ),
            (TCB_CPUSVN_OID, &mut cpusvn),
        ])
        .collect();

        parse_extensions(value, oid_to_compsvn)?;

        Ok(Self {
            compsvn: compsvn.map(Option::unwrap),
            pcesvn: pcesvn.unwrap(),
            _cpusvn: cpusvn.unwrap(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum SgxType {
    Standard,
    Scalable,
}

impl<'a> TryFrom<ExtensionValue<'a>> for SgxType {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Enumerated(v) = value {
            Self::try_from(v)
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

impl TryFrom<asn1::Enumerated> for SgxType {
    type Error = Error;
    fn try_from(value: asn1::Enumerated) -> Result<Self> {
        match value.value() {
            0 => Ok(SgxType::Standard),
            1 => Ok(SgxType::Scalable),
            _ => Err(Error::new("unknown SGX type in PCK certificate")),
        }
    }
}

#[expect(dead_code, reason = "these fields are never read")]
#[derive(Debug)]
pub(crate) struct Configuration {
    // TODO should we let clients specify configuration requirements?
    //   e.g. disallow `smt_enabled = true`
    dynamic_platform: bool,
    cached_keys: bool,
    smt_enabled: bool,
}

impl<'a> TryFrom<ExtensionValue<'a>> for Configuration {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Sequence(v) = value {
            Self::try_from(v)
        } else {
            Err(Error::new("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Configuration {
    type Error = Error;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self> {
        let mut dynamic_platform = None;
        let mut cached_keys = None;
        let mut smt_enabled = None;

        parse_extensions(
            value,
            HashMap::from([
                (
                    CONFIGURATION_DYNAMIC_PLATFORM_OID,
                    &mut dynamic_platform as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (CONFIGURATION_CACHED_KEYS_OID, &mut cached_keys),
                (CONFIGURATION_SMT_ENABLED_OID, &mut smt_enabled),
            ]),
        )?;

        Ok(Self {
            dynamic_platform: dynamic_platform.unwrap(),
            cached_keys: cached_keys.unwrap(),
            smt_enabled: smt_enabled.unwrap(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialization() {
        const DATA: &[u8] = include_bytes!("../../tests/data/sgx_x509_extension.der");

        let ext = SgxPckExtension::from_der(DATA).unwrap();

        assert_eq!(ext.pceid, [0u8, 0u8]);
        assert_eq!(ext.tcb.pcesvn, 11);
        assert_eq!(ext.tcb.compsvn[0], 4);
    }
}
