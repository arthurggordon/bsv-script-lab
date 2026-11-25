//! Independent test signer for the direct-signature GB/T 35275-2026 profile.

use der::asn1::{ObjectIdentifier, OctetStringRef, PrintableStringRef, SetOfVec};
use der::{Encode, Sequence, ValueOrd};
use getrandom::SysRng;
use serde::Serialize;
use sm2::dsa::{Signature, SigningKey, signature::RandomizedSigner};
use sm2::elliptic_curve::sec1::ToSec1Point;
use std::{env, error::Error, io, process::ExitCode};

const USER_ID: &str = "1234567812345678";
const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.1");
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.2");
const OID_SM3_UNKEYED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.401.1");
const OID_SM2_SIGN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301.1");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const SIGNER_VERSION: u8 = 2;
const USAGE: &str = "Usage: sm2-signed-data-signer -message HEX -key TEST_KEY_HEX [-detached]";

#[derive(Clone, Copy, Sequence, ValueOrd)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
}

#[derive(Sequence)]
struct EncapsulatedContentInfo<'a> {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    content: Option<&'a OctetStringRef>,
}

#[derive(Sequence, ValueOrd)]
struct NameAttribute<'a> {
    oid: ObjectIdentifier,
    value: PrintableStringRef<'a>,
}

#[derive(Sequence, ValueOrd)]
struct IssuerAndSerialNumber<'a> {
    issuer: Vec<SetOfVec<NameAttribute<'a>>>,
    serial_number: u8,
}

#[derive(Sequence, ValueOrd)]
struct SignerInfo<'a> {
    version: u8,
    signer_identifier: IssuerAndSerialNumber<'a>,
    digest_algorithm: AlgorithmIdentifier,
    signature_algorithm: AlgorithmIdentifier,
    signature: &'a OctetStringRef,
}

#[derive(Sequence)]
struct SignedData<'a> {
    version: u8,
    digest_algorithms: SetOfVec<AlgorithmIdentifier>,
    content: EncapsulatedContentInfo<'a>,
    signer_infos: SetOfVec<SignerInfo<'a>>,
}

#[derive(Sequence)]
struct ContentInfo<'a> {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: SignedData<'a>,
}

#[derive(Serialize)]
struct Output {
    envelope_hex: String,
    public_key_hex: String,
    signer_identifier_hex: String,
    signer_version: u8,
}

fn fixture_identifier() -> der::Result<IssuerAndSerialNumber<'static>> {
    let organization = NameAttribute {
        oid: OID_ORGANIZATION,
        value: PrintableStringRef::new("BSV Script Lab")?,
    };
    // Preserve the existing DER fixture identity across the provider replacement.
    let common_name = NameAttribute {
        oid: OID_COMMON_NAME,
        value: PrintableStringRef::new("Independent Go Signer")?,
    };
    Ok(IssuerAndSerialNumber {
        issuer: vec![[organization].try_into()?, [common_name].try_into()?],
        serial_number: 1,
    })
}

fn sign(message: &[u8], key: &[u8; 32], detached: bool) -> Result<Output, Box<dyn Error>> {
    let signing_key = SigningKey::from_slice(USER_ID, key).map_err(|_| "invalid SM2 test key")?;
    let signature: Signature = signing_key
        .try_sign_with_rng(&mut SysRng, message)
        .map_err(|_| "SM2 signing failed")?;
    let signature = signature.to_der();
    let public_key = signing_key.verifying_key().to_sec1_point(false);
    let signer_identifier = fixture_identifier()?;
    let signer_identifier_hex = hex::encode(signer_identifier.to_der()?);
    let digest_algorithm = AlgorithmIdentifier {
        algorithm: OID_SM3_UNKEYED,
    };
    let signer_info = SignerInfo {
        version: SIGNER_VERSION,
        signer_identifier,
        digest_algorithm,
        signature_algorithm: AlgorithmIdentifier {
            algorithm: OID_SM2_SIGN,
        },
        signature: OctetStringRef::new(signature.as_bytes())?,
    };
    let envelope = ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: SignedData {
            version: 1,
            digest_algorithms: [digest_algorithm].try_into()?,
            content: EncapsulatedContentInfo {
                content_type: OID_DATA,
                content: (!detached)
                    .then(|| OctetStringRef::new(message))
                    .transpose()?,
            },
            signer_infos: [signer_info].try_into()?,
        },
    };
    Ok(Output {
        envelope_hex: hex::encode(envelope.to_der()?),
        public_key_hex: hex::encode(public_key.as_bytes()),
        signer_identifier_hex,
        signer_version: SIGNER_VERSION,
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mut message = None;
    let mut key = None;
    let mut detached = false;
    while let Some(arg) = args.next() {
        let (flag, value) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(flag, value)| (flag, Some(value)));
        match flag {
            "-h" | "--help" | "-help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "-message" | "--message" => {
                message = Some(
                    value
                        .map(str::to_owned)
                        .or_else(|| args.next())
                        .ok_or(USAGE)?,
                );
            }
            "-key" | "--key" => {
                key = Some(
                    value
                        .map(str::to_owned)
                        .or_else(|| args.next())
                        .ok_or(USAGE)?,
                );
            }
            "-detached" | "--detached" => {
                detached = match value {
                    None | Some("1" | "t" | "T" | "true" | "TRUE" | "True") => true,
                    Some("0" | "f" | "F" | "false" | "FALSE" | "False") => false,
                    _ => return Err(USAGE.into()),
                };
            }
            _ => return Err(USAGE.into()),
        }
    }
    let message = hex::decode(message.ok_or(USAGE)?).map_err(|_| "invalid hex message")?;
    if message.is_empty() {
        return Err("message must not be empty".into());
    }
    let mut scalar = [0; 32];
    hex::decode_to_slice(key.ok_or(USAGE)?, &mut scalar)
        .map_err(|_| "test key must be 32 hex-encoded bytes")?;

    let result = sign(&message, &scalar, detached)?;
    serde_json::to_writer(io::stdout(), &result)?;
    println!();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
