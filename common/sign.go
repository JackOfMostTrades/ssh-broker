package common

import "context"

type SignatureAlgorithm string

const (
	SignatureAlgorithm_SHA1withRSA SignatureAlgorithm = "SHA1withRSA"
	SignatureAlgorithm_SHA256withRSA = "SHA256withRSA"
	SignatureAlgorithm_SHA512withRSA = "SHA512withRSA"
	SignatureAlgorithm_SHA256withECDSA = "SHA256withECDSA"
)

type SignRequest struct {
	PublicKey []byte `json:"publicKey"`
	SignatureAlgorithm SignatureAlgorithm `json:"signatureAlgorithm"`
	Data []byte `json:"data"`
}

type SignResponse struct {
	Signature []byte `json:"signature"`
}

type ListKeysRequest struct {
}

type RemoteKey struct {
	KeyName string `json:"keyName"`
	PublicKey []byte `json:"publicKey"`
}

type ListKeysResponse struct {
	Keys []*RemoteKey `json:"keys"`
}

type SshBroker interface {
	Sign(context.Context, *SignRequest) (*SignResponse, error)
	ListKeys(context.Context, *ListKeysRequest) (*ListKeysResponse, error)
}
