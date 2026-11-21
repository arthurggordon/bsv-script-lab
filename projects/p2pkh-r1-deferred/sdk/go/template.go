// Package deferred constructs and recognizes canonical P2PKH-R1-Deferred scriptPubKeys.
package deferred

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	r1 "github.com/linzhm/bsv-script-lab/projects/p2pkh-r1/sdk/go"
)

const fingerprint = "844eaecb0dc475389c5c3012042d98792243dc6eb84eea78bd7dc3bc4dd28cf6"

type Commitment struct {
	PublicKey          [65]byte
	TargetScriptSHA256 [32]byte
	TargetTxOutHash256 [32]byte
}

func canonical(script []byte) bool {
	if len(script) != 801 {
		return false
	}
	fixed := bytes.Clone(script)
	clear(fixed[10:75])
	clear(fixed[76:108])
	clear(fixed[139:147])
	clear(fixed[166:198])
	hash := sha256.Sum256(fixed)
	return hex.EncodeToString(hash[:]) == fingerprint
}

func LockForKey(template, r1Template, publicKey []byte, satoshis int64) ([]byte, error) {
	if !canonical(template) {
		return nil, errors.New("unrecognized deferred template")
	}
	if satoshis < 0 || satoshis > 2_100_000_000_000_000 {
		return nil, errors.New("invalid amount")
	}
	target, err := r1.LockForKey(r1Template, publicKey)
	if err != nil {
		return nil, err
	}
	value := binary.LittleEndian.AppendUint64(nil, uint64(satoshis))
	output := append(bytes.Clone(value), 0xfd)
	output = binary.LittleEndian.AppendUint16(output, uint16(len(target)))
	output = append(output, target...)
	hash := sha256.Sum256(output)
	outputHash := sha256.Sum256(hash[:])
	if outputHash == [32]byte{} {
		return nil, errors.New("zero target commitment")
	}
	scriptHash := sha256.Sum256(target)
	script := bytes.Clone(template)
	copy(script[10:75], publicKey)
	copy(script[76:108], scriptHash[:])
	copy(script[139:147], value)
	copy(script[166:198], outputHash[:])
	return script, nil
}

func Recognize(r1Template, script []byte, satoshis int64) (Commitment, bool) {
	if len(script) != 801 {
		return Commitment{}, false
	}
	key := script[10:75]
	expected, err := LockForKey(script, r1Template, key, satoshis)
	if err != nil || !bytes.Equal(expected, script) {
		return Commitment{}, false
	}
	return Commitment{[65]byte(key), [32]byte(script[76:108]), [32]byte(script[166:198])}, true
}

// ActivationWitness encodes a preimage built from the actual batch and authenticated prevout.
func ActivationWitness(r1Template, script []byte, satoshis int64, preimage []byte) ([]byte, error) {
	commitment, ok := Recognize(r1Template, script, satoshis)
	if !ok || len(preimage) != 158 || !bytes.Equal(preimage[104:106], []byte{1, 0xac}) ||
		binary.LittleEndian.Uint64(preimage[106:114]) != uint64(satoshis) ||
		binary.LittleEndian.Uint32(preimage[154:]) != 0x43 ||
		!bytes.Equal(preimage[118:150], commitment.TargetTxOutHash256[:]) {
		return nil, errors.New("activation preimage does not match the funding output")
	}
	return append([]byte{0x4c, 158}, preimage...), nil
}
