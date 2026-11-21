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

const fingerprint = "f73e2c43cabf95938529d89802b8cbea957932c51b13a3265261a5087c1c316d"

type Commitment struct {
	PublicKey          [65]byte
	TargetScriptSHA256 [32]byte
	TargetTxOutHash256 [32]byte
}

func canonical(script []byte) bool {
	if len(script) != 1480 {
		return false
	}
	fixed := bytes.Clone(script)
	clear(fixed[1:66])
	clear(fixed[67:99])
	clear(fixed[154:162])
	clear(fixed[179:211])
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
	copy(script[1:66], publicKey)
	copy(script[67:99], scriptHash[:])
	copy(script[154:162], value)
	copy(script[179:211], outputHash[:])
	return script, nil
}

func Recognize(r1Template, script []byte, satoshis int64) (Commitment, bool) {
	if len(script) != 1480 {
		return Commitment{}, false
	}
	key := script[1:66]
	expected, err := LockForKey(script, r1Template, key, satoshis)
	if err != nil || !bytes.Equal(expected, script) {
		return Commitment{}, false
	}
	return Commitment{[65]byte(key), [32]byte(script[67:99]), [32]byte(script[179:211])}, true
}

// ActivationWitness encodes the paired output preimage and optional type byte plus selected transaction digest.
func ActivationWitness(r1Template, script []byte, satoshis int64, preimage []byte, auxiliary ...[]byte) ([]byte, error) {
	if len(auxiliary) > 1 {
		return nil, errors.New("expected at most one auxiliary activation digest")
	}
	code := []byte{1, 0xac}
	if len(auxiliary) == 1 {
		code = []byte{4, 0xad, 0x68, 0xab, 0xac}
	}
	valueOffset := 104 + len(code)
	commitment, ok := Recognize(r1Template, script, satoshis)
	if !ok || len(preimage) != valueOffset+52 || !bytes.Equal(preimage[104:valueOffset], code) ||
		binary.LittleEndian.Uint64(preimage[valueOffset:]) != uint64(satoshis) ||
		!bytes.Equal(preimage[valueOffset+12:valueOffset+44], commitment.TargetTxOutHash256[:]) {
		return nil, errors.New("activation preimage does not match the funding output")
	}
	bindingType := binary.LittleEndian.Uint32(preimage[len(preimage)-4:])
	if bindingType != 0x43 && bindingType != 0xc3 {
		return nil, errors.New("expected ForkID SINGLE")
	}
	var witness []byte
	if len(auxiliary) == 1 {
		extra := auxiliary[0]
		if len(extra) != 33 {
			return nil, errors.New("invalid auxiliary activation digest")
		}
		mode := extra[0]
		if mode&0x5f < 0x41 || mode&0x5f > 0x43 || mode == 0x43 || mode == 0xc3 ||
			uint32(mode&0x80) != bindingType&0x80 {
			return nil, errors.New("invalid auxiliary activation type")
		}
		witness = append([]byte{33}, extra...)
	}
	return append(append(witness, 0x4c, byte(len(preimage))), preimage...), nil
}
