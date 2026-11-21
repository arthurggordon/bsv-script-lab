import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { lockForKey as r1LockForKey } from "../../../p2pkh-r1/sdk/typescript/index.ts";

const fields = [[10, 75], [76, 108], [139, 147], [166, 198]] as const;
const fingerprint = "844eaecb0dc475389c5c3012042d98792243dc6eb84eea78bd7dc3bc4dd28cf6";
const zero = Buffer.alloc(32);

function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

function canonical(script: Uint8Array): boolean {
  if (script.length !== 801) return false;
  const fixed = Buffer.from(script);
  for (const [start, end] of fields) fixed.fill(0, start, end);
  return sha256(fixed).toString("hex") === fingerprint;
}

export function lockForKey(template: Uint8Array, r1Template: Uint8Array,
  publicKey: Uint8Array, satoshis: bigint): Buffer {
  if (!canonical(template)) throw new Error("unrecognized deferred template");
  if (satoshis < 0n || satoshis > 2_100_000_000_000_000n) throw new RangeError("invalid amount");
  const target = r1LockForKey(r1Template, publicKey);
  const header = Buffer.alloc(11);
  header.writeBigUInt64LE(satoshis);
  header[8] = 0xfd;
  header.writeUInt16LE(target.length, 9);
  const outputHash = sha256(sha256(Buffer.concat([header, target])));
  if (outputHash.equals(zero)) throw new Error("zero target commitment");
  const script = Buffer.from(template);
  script.set(publicKey, 10);
  script.set(sha256(target), 76);
  script.set(header.subarray(0, 8), 139);
  script.set(outputHash, 166);
  return script;
}

export interface Commitment {
  publicKey: Buffer;
  targetScriptSha256: Buffer;
  targetTxOutHash256: Buffer;
}

export function recognize(r1Template: Uint8Array, rawScript: Uint8Array,
  satoshis: bigint): Commitment | null {
  const script = Buffer.from(rawScript);
  const publicKey = script.subarray(10, 75);
  try {
    if (!lockForKey(script, r1Template, publicKey, satoshis).equals(script)) return null;
  } catch {
    return null;
  }
  return {publicKey, targetScriptSha256: script.subarray(76, 108), targetTxOutHash256: script.subarray(166, 198)};
}

/** Encode a preimage already built from the actual batch and authenticated prevout. */
export function activationWitness(r1Template: Uint8Array, script: Uint8Array,
  satoshis: bigint, preimage: Uint8Array): Buffer {
  const commitment = recognize(r1Template, script, satoshis);
  const pre = Buffer.from(preimage);
  if (!commitment || pre.length !== 158 || pre.readUInt16BE(104) !== 0x01ac ||
      pre.readBigUInt64LE(106) !== satoshis || pre.readUInt32LE(154) !== 0x43 ||
      !pre.subarray(118, 150).equals(commitment.targetTxOutHash256))
    throw new Error("activation preimage does not match the funding output");
  return Buffer.concat([Buffer.from([0x4c, 158]), pre]);
}
