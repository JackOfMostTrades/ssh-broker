package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/jackofmosttrades/ssh-broker/common"
	"github.com/jackofmosttrades/ssh-broker/server/ssh-broker-plugin"
	"net/http"
)

type sshBrokerImpl struct {
	authzPlugin ssh_broker_plugin.SshBrokerAuthzPlugin
	keyData     []*KeyData
}

func (s *sshBrokerImpl) isCallerAuthorizedForKey(ctx context.Context, keyData *KeyData) (bool, error) {
	if s.authzPlugin == nil {
		return true, nil
	}
	if caller, ok := ctx.Value(callerKey{}).(*x509.Certificate); ok {
		return s.authzPlugin.IsAuthorized(caller, keyData.Name, keyData.Metadata)
	} else {
		return false, nil
	}
}

func (s *sshBrokerImpl) Sign(ctx context.Context, request *common.SignRequest) (*common.SignResponse, error) {
	for _, key := range s.keyData {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.Signer.Public())
		if err != nil {
			return nil, fmt.Errorf("unable to marshal public key: %w", err)
		}
		if bytes.Equal(pubKeyBytes, request.PublicKey) {
			if isAuthorized, err := s.isCallerAuthorizedForKey(ctx, key); err != nil {
				return nil, fmt.Errorf("unable to authorize caller: %w", err)
			} else if !isAuthorized {
				continue
			}

			var hash crypto.Hash
			switch request.SignatureAlgorithm {
			case common.SignatureAlgorithm_SHA1withRSA:
				hash = crypto.SHA1
			case common.SignatureAlgorithm_SHA256withRSA:
				hash = crypto.SHA256
			case common.SignatureAlgorithm_SHA512withRSA:
				hash = crypto.SHA512
			case common.SignatureAlgorithm_SHA256withECDSA:
				hash = crypto.SHA256
			default:
				return nil, fmt.Errorf("invalid signature algorithm: %s", request.SignatureAlgorithm)
			}

			var digest []byte
			if request.IsDigested {
				digest = request.Data
			} else {
				h := hash.New()
				h.Write(request.Data)
				digest = h.Sum(nil)
			}

			sig, err := key.Signer.Sign(rand.Reader, digest, hash)
			if err != nil {
				return nil, fmt.Errorf("unable to generate signature: %w", err)
			}
			return &common.SignResponse{
				Signature: sig,
			}, nil
		}
	}

	return nil, &httpError{"invalid public key", http.StatusBadRequest}
}

func (s *sshBrokerImpl) ListKeys(ctx context.Context, request *common.ListKeysRequest) (*common.ListKeysResponse, error) {
	keys := make([]*common.RemoteKey, 0, len(s.keyData))
	for _, key := range s.keyData {
		if isAuthorized, err := s.isCallerAuthorizedForKey(ctx, key); err != nil {
			return nil, fmt.Errorf("unable to authorize caller: %w", err)
		} else if !isAuthorized {
			continue
		}

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.Signer.Public())
		if err != nil {
			return nil, fmt.Errorf("unable to marshal public key: %w", err)
		}
		keys = append(keys, &common.RemoteKey{
			KeyName:   key.Name,
			PublicKey: pubKeyBytes,
		})
	}
	return &common.ListKeysResponse{
		Keys: keys,
	}, nil
}
