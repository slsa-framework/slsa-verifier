package utils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	intotoAttestations "github.com/in-toto/attestation/go/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func EnvelopeFromBytes(payload []byte) (*dsselib.Envelope, error) {
	var env dsselib.Envelope
	err := json.Unmarshal(payload, &env)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("%w: expected payload type %q, got %q",
			serrors.ErrorInvalidDssePayload, intoto.PayloadType, env.PayloadType)
	}
	return &env, nil
}

func PayloadFromEnvelope(env *dsselib.Envelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", serrors.ErrorInvalidFormat)
	}
	return payload, nil
}

// StatementFromBytes parses the provided byte slice as a JSON payload and returns an intoto.Statement.
// Ideally, we use the "V1" Statement in https://pkg.go.dev/github.com/in-toto/attestation/go/v1#pkg-constants,
// but it parses json fields in snake case, while the official spec uses camel case
// https://github.com/in-toto/attestation/blob/v1.0/spec/v1.0/statement.md.
func StatementFromBytes(payload []byte) (*intoto.Statement, error) {
	var statement intoto.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	if statement.Type != intoto.StatementInTotoV01 && statement.Type != intotoAttestations.StatementTypeUri {
		return nil, fmt.Errorf("%w: invalid statement type: %q", serrors.ErrorInvalidDssePayload, statement.Type)
	}
	return &statement, nil
}

func StatementFromEnvelope(env *dsselib.Envelope) (*intoto.Statement, error) {
	payload, err := PayloadFromEnvelope(env)
	if err != nil {
		return nil, err
	}
	statement, err := StatementFromBytes(payload)
	if err != nil {
		return nil, err
	}
	return statement, nil
}

func DecodeSignature(s string) ([]byte, error) {
	var errs []error
	// First try the std decoding.
	rsig, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	// If std decoding failed, try URL decoding.
	// We try both because we encountered decoding failures
	// during our tests. The DSSE documentation does not prescribe
	// which encoding to use: `Either standard or URL-safe encoding is allowed`.
	// https://github.com/secure-systems-lab/dsse/blob/27ce241dec575998dee8967c3c76d4edd5d6ee73/envelope.md#standard-json-envelope.
	rsig, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	return nil, fmt.Errorf("%w: %v", serrors.ErrorInvalidEncoding, errs)
}

type SignatureEncoding int

const (
	// The DER signature is encoded using ASN.1
	// (https://tools.ietf.org/html/rfc5480#appendix-A):
	// ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }. In particular, the
	// encoding is:
	// 0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
	SignatureEncodingDER SignatureEncoding = iota
	// The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
	// and have the same size in bytes as the order of the curve. For example, for
	// NIST P-256 curve, r and s are zero-padded to 32 bytes.
	SignatureEncodingIEEEP1363
)

type publicKey struct {
	keyID       string
	pubKey      *crypto.PublicKey
	sigEncoding SignatureEncoding // Default is SignatureEncodingDER.
}

func (p *publicKey) Verify(ctx context.Context, data, sig []byte) error {
	digest := sha256.Sum256(data)
	if p.pubKey == nil {
		return fmt.Errorf("%w: key is empty", serrors.ErrorInternal)
	}
	switch v := (*p.pubKey).(type) {
	default:
		return fmt.Errorf("unknown key type: %T", v)
	case *ecdsa.PublicKey:
		switch p.sigEncoding {
		case SignatureEncodingDER:
			if !ecdsa.VerifyASN1(v, digest[:], sig) {
				return fmt.Errorf("%w: cannot verify signature",
					serrors.ErrorInvalidSignature)
			}
		case SignatureEncodingIEEEP1363:
			r := new(big.Int)
			r.SetBytes(sig[:32])
			s := new(big.Int)
			s.SetBytes(sig[32:])
			if !ecdsa.Verify(v, digest[:], r, s) {
				return fmt.Errorf("%w: cannot verify signature",
					serrors.ErrorInvalidSignature)
			}
		default:
			return fmt.Errorf("unsupported encoding: %v", p.sigEncoding)
		}
	}
	return nil
}

// KeyID implements dsse.Verifier.KeyID.
func (p *publicKey) KeyID() (string, error) {
	return p.keyID, nil
}

// Public implements dsse.Verifier.Public.
func (p *publicKey) Public() crypto.PublicKey {
	return p.pubKey
}

type KeyFormat int

const (
	KeyFormatDER KeyFormat = iota
	KeyFormatPEM
)

func DsseVerifierNew(content []byte, format KeyFormat, keyID string, sigEncoding *SignatureEncoding) (*dsselib.EnvelopeVerifier, error) {
	if format == KeyFormatPEM {
		block, rest := pem.Decode(content)
		if len(rest) != 0 {
			return nil, fmt.Errorf("%w: additional data found", serrors.ErrorInvalidPEM)
		}
		if block == nil {
			return nil, fmt.Errorf("%w: unable to decode PEM format", serrors.ErrorInvalidPEM)
		}
		content = block.Bytes
	}

	key, err := x509.ParsePKIXPublicKey(content)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidPublicKey, err)
	}

	pubKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not a public key", serrors.ErrorInvalidPublicKey)
	}

	dssePubKey := publicKey{
		pubKey: &pubKey,
		keyID:  keyID,
	}
	if sigEncoding != nil {
		dssePubKey.sigEncoding = *sigEncoding
	}

	verifier, err := dsselib.NewEnvelopeVerifier(&dssePubKey)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return verifier, nil
}
