//! Construct and recognize canonical P2PKH-R1-Deferred raw scriptPubKeys.
use sha2::{Digest, Sha256};

const FIELDS: [(usize, usize); 4] = [(1, 66), (67, 99), (154, 162), (179, 211)];
const FINGERPRINT: [u8; 32] = [
    0xf7, 0x3e, 0x2c, 0x43, 0xca, 0xbf, 0x95, 0x93, 0x85, 0x29, 0xd8, 0x98, 0x02, 0xb8, 0xcb, 0xea,
    0x95, 0x79, 0x32, 0xc5, 0x1b, 0x13, 0xa3, 0x26, 0x52, 0x61, 0xa5, 0x08, 0x7c, 0x1c, 0x31, 0x6d,
];

#[derive(Debug, PartialEq, Eq)]
pub struct Commitment {
    pub public_key: [u8; 65],
    pub target_script_sha256: [u8; 32],
    pub target_txout_hash256: [u8; 32],
}

fn canonical(script: &[u8]) -> bool {
    let Ok(mut fixed) = <[u8; 1480]>::try_from(script) else {
        return false;
    };
    for (start, end) in FIELDS {
        fixed[start..end].fill(0);
    }
    Sha256::digest(fixed)[..] == FINGERPRINT
}

pub fn lock_for_key(
    template: &[u8],
    r1_template: &[u8],
    public_key: &[u8],
    satoshis: u64,
) -> Result<Vec<u8>, &'static str> {
    if !canonical(template) {
        return Err("unrecognized deferred template");
    }
    if satoshis > 2_100_000_000_000_000 {
        return Err("invalid amount");
    }
    let target = p2pkh_r1::lock_for_key(r1_template, public_key)?;
    let mut output_hash = Sha256::new();
    output_hash.update(satoshis.to_le_bytes());
    output_hash.update([0xfd]);
    output_hash.update((target.len() as u16).to_le_bytes());
    output_hash.update(&target);
    let output_hash = Sha256::digest(output_hash.finalize());
    if output_hash[..] == [0; 32] {
        return Err("zero target commitment");
    }
    let mut script = template.to_vec();
    script[1..66].copy_from_slice(public_key);
    script[67..99].copy_from_slice(&Sha256::digest(target));
    script[154..162].copy_from_slice(&satoshis.to_le_bytes());
    script[179..211].copy_from_slice(&output_hash);
    Ok(script)
}

pub fn recognize(r1_template: &[u8], script: &[u8], satoshis: u64) -> Option<Commitment> {
    let public_key: [u8; 65] = script.get(1..66)?.try_into().ok()?;
    if lock_for_key(script, r1_template, &public_key, satoshis).ok()? != script {
        return None;
    }
    Some(Commitment {
        public_key,
        target_script_sha256: script[67..99].try_into().ok()?,
        target_txout_hash256: script[179..211].try_into().ok()?,
    })
}

/// Encode a direct ForkID SINGLE activation.
pub fn activation_witness(
    r1_template: &[u8],
    script: &[u8],
    satoshis: u64,
    preimage: &[u8],
) -> Result<Vec<u8>, &'static str> {
    activation_witness_with_digest(r1_template, script, satoshis, preimage, None)
}

/// Encode the output-check preimage and optional type byte plus selected digest.
pub fn activation_witness_with_digest(
    r1_template: &[u8],
    script: &[u8],
    satoshis: u64,
    preimage: &[u8],
    auxiliary: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let commitment = recognize(r1_template, script, satoshis).ok_or("wrong funding lock")?;
    let code: &[u8] = if auxiliary.is_some() {
        &[4, 0xad, 0x68, 0xab, 0xac]
    } else {
        &[1, 0xac]
    };
    let value_offset = 104 + code.len();
    if preimage.len() != value_offset + 52
        || &preimage[104..value_offset] != code
        || preimage[value_offset..value_offset + 8] != satoshis.to_le_bytes()
        || preimage[value_offset + 12..value_offset + 44] != commitment.target_txout_hash256
    {
        return Err("activation preimage does not match the funding output");
    }
    let binding_type = u32::from_le_bytes(preimage[preimage.len() - 4..].try_into().unwrap());
    if !matches!(binding_type, 0x43 | 0xc3) {
        return Err("expected ForkID SINGLE");
    }
    let mut witness = Vec::new();
    if let Some(extra) = auxiliary {
        let [mode, ..] =
            <[u8; 33]>::try_from(extra).map_err(|_| "invalid auxiliary activation digest")?;
        if !matches!(mode & 0x5f, 0x41..=0x43)
            || matches!(mode, 0x43 | 0xc3)
            || u32::from(mode & 0x80) != binding_type & 0x80
        {
            return Err("invalid auxiliary activation type");
        }
        witness.push(33);
        witness.extend_from_slice(extra);
    }
    witness.extend_from_slice(&[0x4c, preimage.len() as u8]);
    witness.extend_from_slice(preimage);
    Ok(witness)
}
