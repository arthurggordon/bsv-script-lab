//! Construct and recognize canonical P2PKH-R1-Deferred raw scriptPubKeys.
use sha2::{Digest, Sha256};

const FIELDS: [(usize, usize); 4] = [(10, 75), (76, 108), (139, 147), (166, 198)];
const FINGERPRINT: [u8; 32] = [
    0x84, 0x4e, 0xae, 0xcb, 0x0d, 0xc4, 0x75, 0x38, 0x9c, 0x5c, 0x30, 0x12, 0x04, 0x2d, 0x98, 0x79,
    0x22, 0x43, 0xdc, 0x6e, 0xb8, 0x4e, 0xea, 0x78, 0xbd, 0x7d, 0xc3, 0xbc, 0x4d, 0xd2, 0x8c, 0xf6,
];

#[derive(Debug, PartialEq, Eq)]
pub struct Commitment {
    pub public_key: [u8; 65],
    pub target_script_sha256: [u8; 32],
    pub target_txout_hash256: [u8; 32],
}

fn canonical(script: &[u8]) -> bool {
    let Ok(mut fixed) = <[u8; 801]>::try_from(script) else {
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
    script[10..75].copy_from_slice(public_key);
    script[76..108].copy_from_slice(&Sha256::digest(target));
    script[139..147].copy_from_slice(&satoshis.to_le_bytes());
    script[166..198].copy_from_slice(&output_hash);
    Ok(script)
}

pub fn recognize(r1_template: &[u8], script: &[u8], satoshis: u64) -> Option<Commitment> {
    let public_key: [u8; 65] = script.get(10..75)?.try_into().ok()?;
    if lock_for_key(script, r1_template, &public_key, satoshis).ok()? != script {
        return None;
    }
    Some(Commitment {
        public_key,
        target_script_sha256: script[76..108].try_into().ok()?,
        target_txout_hash256: script[166..198].try_into().ok()?,
    })
}

/// Encode a preimage built from the actual batch and authenticated prevout.
pub fn activation_witness(
    r1_template: &[u8],
    script: &[u8],
    satoshis: u64,
    preimage: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let commitment = recognize(r1_template, script, satoshis).ok_or("wrong funding lock")?;
    if preimage.len() != 158
        || preimage[104..106] != [1, 0xac]
        || preimage[106..114] != satoshis.to_le_bytes()
        || preimage[154..] != 0x43u32.to_le_bytes()
        || preimage[118..150] != commitment.target_txout_hash256
    {
        return Err("activation preimage does not match the funding output");
    }
    let mut witness = vec![0x4c, 158];
    witness.extend_from_slice(preimage);
    Ok(witness)
}
