package server

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
)

type KeyData struct {
	Name       string                 `json:"name"`
	PrivateKey []byte                 `json:"privateKey"`
	Signer     crypto.Signer          `json:"-"`
	Metadata   map[string]interface{} `json:"metadata"`
}

func LoadKeyDataFile(filename string) ([]*KeyData, error) {
	var keyData []*KeyData
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open file for reading %s: %w", filename, err)
	}
	err = json.NewDecoder(f).Decode(&keyData)
	if err != nil {
		return nil, fmt.Errorf("unable to JSON-parse key data file %s: %w", filename, err)
	}
	for _, key := range keyData {
		pkey, err := x509.ParsePKCS8PrivateKey(key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key %s: %w", key.Name, err)
		}
		key.Signer = pkey.(crypto.Signer)
	}

	return keyData, nil
}
