package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/sm2"
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	oidSM3        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	oidSM3Unkeyed = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}
	oidSM2Sign    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
	oidSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
)

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"tag:0,explicit,optional"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version            int
	SignerIdentifier   issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	Content          encapsulatedContentInfo
	SignerInfos      []signerInfo `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type output struct {
	EnvelopeHex         string `json:"envelope_hex"`
	PublicKeyHex        string `json:"public_key_hex"`
	SignerIdentifierHex string `json:"signer_identifier_hex"`
	SignerVersion       int    `json:"signer_version"`
}

func main() {
	messageHex := flag.String("message", "", "hex-encoded message")
	keyHex := flag.String("key", "", "hex-encoded 32-byte test private key")
	detached := flag.Bool("detached", false, "omit the signed content")
	signerVersion := flag.Int("signer-version", 2, "SignerInfo version (1 or 2)")
	flag.Parse()

	signatureAlgorithm := oidSM2Sign
	digestAlgorithm := oidSM3Unkeyed
	switch *signerVersion {
	case 1:
		signatureAlgorithm = oidSM2WithSM3
		digestAlgorithm = oidSM3
	case 2:
	default:
		fail(fmt.Errorf("SignerInfo version must be 1 or 2"))
	}

	message, err := hex.DecodeString(*messageHex)
	if err != nil {
		fail(err)
	}
	keyBytes, err := hex.DecodeString(*keyHex)
	if err != nil {
		fail(err)
	}
	privateKey, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		fail(err)
	}
	signature, err := privateKey.Sign(rand.Reader, message,
		sm2.NewSM2SignerOption(true, []byte("1234567812345678")))
	if err != nil {
		fail(err)
	}

	issuerDER, err := asn1.Marshal(pkix.Name{
		Organization: []string{"BSV Script Lab"},
		CommonName:   "Independent Go Signer",
	}.ToRDNSequence())
	if err != nil {
		fail(err)
	}
	identifier := issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: issuerDER},
		SerialNumber: big.NewInt(1),
	}
	identifierDER, err := asn1.Marshal(identifier)
	if err != nil {
		fail(err)
	}
	encapsulated := encapsulatedContentInfo{ContentType: oidData}
	if !*detached {
		encapsulated.Content = message
	}
	body, err := asn1.Marshal(signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: digestAlgorithm}},
		Content:          encapsulated,
		SignerInfos: []signerInfo{{
			Version:            *signerVersion,
			SignerIdentifier:   identifier,
			DigestAlgorithm:    algorithmIdentifier{Algorithm: digestAlgorithm},
			SignatureAlgorithm: algorithmIdentifier{Algorithm: signatureAlgorithm},
			Signature:          signature,
		}},
	})
	if err != nil {
		fail(err)
	}
	envelope, err := asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: body},
	})
	if err != nil {
		fail(err)
	}
	publicKey := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	if err := json.NewEncoder(os.Stdout).Encode(output{
		EnvelopeHex:         hex.EncodeToString(envelope),
		PublicKeyHex:        hex.EncodeToString(publicKey),
		SignerIdentifierHex: hex.EncodeToString(identifierDER),
		SignerVersion:       *signerVersion,
	}); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
