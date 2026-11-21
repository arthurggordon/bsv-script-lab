import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { activationWitness, lockForKey, recognize } from "./index.ts";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const template = Buffer.from(read("../../template/template.hex").replace(/\s/g, ""), "hex");
const r1 = Buffer.from(read("../../../p2pkh-r1/template/template.hex").replace(/\s/g, ""), "hex");

test("generation, recognition and activation vectors", () => {
  const layout = JSON.parse(read("../../template/layout.json"));
  const activation = JSON.parse(read("../../template/activation-single.json"));
  const modes = JSON.parse(read("../../template/sighash-modes.json"));
  for (const v of layout.vectors) {
    const satoshis = BigInt(v.value_sats);
    const script = lockForKey(template, r1, Buffer.from(v.public_key_x963, "hex"), satoshis);
    assert.equal(createHash("sha256").update(script).digest("hex"), v.locking_script_sha256);
    const commitment = recognize(r1, script, satoshis);
    assert.ok(commitment);
    assert.equal(commitment.publicKey.toString("hex"), v.public_key_x963);
    assert.equal(commitment.targetScriptSha256.toString("hex"), v.target_script_sha256);
    assert.equal(commitment.targetTxOutHash256.toString("hex"), v.target_txout_hash256);
    assert.equal(recognize(r1, script, satoshis + 1n), null);
    if (v.id !== activation.vector_id) continue;
    const pre = Buffer.from(activation.activation_preimage_hex, "hex");
    assert.equal(activationWitness(r1, script, satoshis, pre).toString("hex"), activation.unlocking_script_hex);
    pre[118] ^= 1;
    assert.throws(() => activationWitness(r1, script, satoshis, pre));
    for (const mode of modes.cases) {
      const paired = Buffer.from(mode.activation_preimage_hex, "hex");
      const auxiliary = mode.auxiliary_hex ? Buffer.from(mode.auxiliary_hex, "hex") : undefined;
      assert.equal(activationWitness(r1, script, satoshis, paired, auxiliary).toString("hex"), mode.unlocking_script_hex);
      if (auxiliary) {
        auxiliary[0] ^= 0x80;
        assert.throws(() => activationWitness(r1, script, satoshis, paired, auxiliary));
      }
    }
  }
});
