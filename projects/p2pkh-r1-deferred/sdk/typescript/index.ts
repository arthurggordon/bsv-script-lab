import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { lockForKey as r1LockForKey } from "../../../p2pkh-r1/sdk/typescript/index.ts";

const fields = [[1, 66], [67, 99], [154, 162], [179, 211]] as const;
const fingerprint = "f73e2c43cabf95938529d89802b8cbea957932c51b13a3265261a5087c1c316d";
const zero = Buffer.alloc(32);

function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

function canonical(script: Uint8Array): boolean {
  if (script.length !== 1480) return false;
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
  script.set(publicKey, 1);
  script.set(sha256(target), 67);
  script.set(header.subarray(0, 8), 154);
  script.set(outputHash, 179);
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
  const publicKey = script.subarray(1, 66);
  try {
    if (!lockForKey(script, r1Template, publicKey, satoshis).equals(script)) return null;
  } catch {
    return null;
  }
  return {publicKey, targetScriptSha256: script.subarray(67, 99), targetTxOutHash256: script.subarray(179, 211)};
}

/** Encode the paired output preimage and optional type byte plus selected transaction digest. */
export function activationWitness(r1Template: Uint8Array, script: Uint8Array,
  satoshis: bigint, preimage: Uint8Array, auxiliary?: Uint8Array): Buffer {
  const commitment = recognize(r1Template, script, satoshis);
  const pre = Buffer.from(preimage);
  const code = Buffer.from(auxiliary ? "04ad68abac" : "01ac", "hex");
  const valueOffset = 104 + code.length;
  if (!commitment || pre.length !== valueOffset + 52 || !pre.subarray(104, valueOffset).equals(code) ||
      pre.readBigUInt64LE(valueOffset) !== satoshis ||
      !pre.subarray(valueOffset + 12, valueOffset + 44).equals(commitment.targetTxOutHash256))
    throw new Error("activation preimage does not match the funding output");
  const bindingType = pre.readUInt32LE(pre.length - 4);
  if (bindingType !== 0x43 && bindingType !== 0xc3) throw new Error("expected ForkID SINGLE");
  const bound = Buffer.concat([Buffer.from([0x4c, pre.length]), pre]);
  if (!auxiliary) return bound;
  const type = auxiliary[0];
  const normalized = type & 0x5f;
  if (auxiliary.length !== 33 || normalized < 0x41 || normalized > 0x43 ||
      type === 0x43 || type === 0xc3 || (type & 0x80) !== (bindingType & 0x80))
    throw new Error("invalid auxiliary activation digest");
  return Buffer.concat([Buffer.from([33]), auxiliary, bound]);
}
