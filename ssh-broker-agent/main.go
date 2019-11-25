package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"github.com/jackofmosttrades/ssh-broker/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Agent struct {
	sshKeyNames []string
	broker common.SshBroker
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (*Agent) Add(key agent.AddedKey) error {
	return errors.New("not implemented")
}

func (*Agent) Lock(passphrase []byte) error {
	return errors.New("not implemented")
}

func (*Agent) Remove(key ssh.PublicKey) error {
	return errors.New("not implemented")
}

func (*Agent) RemoveAll() error {
	return errors.New("not implemented")
}

func (*Agent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("not implemented")
}

func (*Agent) Unlock(passphrase []byte) error {
	return errors.New("not implemented")
}

func (a *Agent) List() ([]*agent.Key, error) {
	resp, err := a.broker.ListKeys(context.Background(), &common.ListKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("unable to get remote key list: %w", err)
	}

	keys := make([]*agent.Key, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		// If filtering with sshKeyNames, only include this key if it is in the name list
		if len(a.sshKeyNames) > 0 {
			found := false
			for _, name := range a.sshKeyNames {
				if name == k.KeyName {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		pubKey, err := x509.ParsePKIXPublicKey(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse remote public key: %w", err)
		}
		sshPubKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert public key to SSH key: %T %w", pubKey, err)
		}
		keys = append(keys, &agent.Key{
			Format: sshPubKey.Type(),
			Blob: sshPubKey.Marshal(),
			Comment: k.KeyName,
		})
	}

	return keys, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sshPubKey, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, fmt.Errorf("unable to parse requested key: %w", err)
	}

	var pubKey crypto.PublicKey
	if cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey); ok {
		pubKey = cryptoPubKey.CryptoPublicKey()
	} else {
		return nil, fmt.Errorf("unable to extract crypto pub key from this key type: %s", sshPubKey.Type())
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal PKIX public key: %w", err)
	}

	var algo common.SignatureAlgorithm
	var format string
	switch key.Type() {
		case ssh.KeyAlgoRSA:
			if (flags & agent.SignatureFlagRsaSha256) != 0 {
				algo = common.SignatureAlgorithm_SHA256withRSA
				format = ssh.SigAlgoRSASHA2512
			} else if (flags & agent.SignatureFlagRsaSha512) != 0 {
				algo = common.SignatureAlgorithm_SHA512withRSA
				format = ssh.SigAlgoRSASHA2512
			} else {
				algo = common.SignatureAlgorithm_SHA1withRSA
				format = ssh.SigAlgoRSA
			}
		case ssh.KeyAlgoECDSA256:
			algo = common.SignatureAlgorithm_SHA256withECDSA
			format = ssh.KeyAlgoECDSA256
		default:
			return nil, fmt.Errorf("unsupport key type: %s", key.Type())
	}

	sig, err := a.broker.Sign(context.Background(), &common.SignRequest{
		PublicKey: pubKeyBytes,
		SignatureAlgorithm: algo,
		Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to remote sign: %w", err)
	}

	var blob []byte = sig.Signature

	// ECDSA signature comes back ASN.1 encoded and we need to change it to SSH encoded
	if format == ssh.KeyAlgoECDSA256 {
		type asn1Signature struct {
			R, S *big.Int
		}
		asn1Sig := new(asn1Signature)
		_, err := asn1.Unmarshal(blob, asn1Sig)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		blob = ssh.Marshal(asn1Sig)
	}

	return &ssh.Signature{
		Format: format,
		Blob: blob,
	}, nil
}

type arrayFlags []string
func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	flagSet := flag.NewFlagSet("ssh-broker-agent", flag.ContinueOnError)
	hostname := flagSet.String("hostname", "", "Hostname (and optionally port) of ssh-broker service")
	certPath := flagSet.String("cert", "", "Path to client certificate")
	keyPath := flagSet.String("key", "", "Path to client key")
	caCertPath := flagSet.String("caCert", "", "Path to CA certificate file. If omitted system defaults with be used.")
	socketPath := flagSet.String("socketPath", "/tmp/ssh-broker-agent.sock", "Path on which to listen for SSH broker agent clients.")

	sshKeyNames := new(arrayFlags)
	flagSet.Var(sshKeyNames, "sshKeyName", "Only list SSH keys with this name. This argument can be repeated.")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if *hostname == "" {
		fmt.Print("--hostname flag is required")
		os.Exit(1)
	}

	tlsConfig := &tls.Config{}
	if *certPath != "" && *keyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Printf("Unable to load client certificate/key: %v", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	if *caCertPath != "" {
		caCertPool := x509.NewCertPool()
		caCertPemBytes, err := ioutil.ReadFile(*caCertPath)
		if err != nil {
			fmt.Printf("Unable to load CA certificates file: %v", err)
			os.Exit(1)
		}
		if !caCertPool.AppendCertsFromPEM(caCertPemBytes) {
			fmt.Printf("Unable to load any CA certificates from file %s", *caCertPath)
			os.Exit(1)
		}
		tlsConfig.RootCAs = caCertPool
	}

	var a agent.ExtendedAgent = &Agent{
		sshKeyNames: *sshKeyNames,
		broker: &SshBrokerClient{
			hostname: *hostname,
			tlsConfig: tlsConfig,
		},
	}

	if os.Stat(*socketPath); err == nil {
		conn, err := net.Dial("unix", *socketPath)
		if err != nil {
			os.Remove(*socketPath)
		} else {
			conn.Close()
			log.Println("Detected already listening agent...")
			return
		}
	}

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	defer os.Remove(*socketPath)

	shuttingDown := false
	go func() {
		for {
			c, err := listener.Accept()
			if shuttingDown {
				return
			}
			if err != nil {
				log.Printf("Error accepting connection: %v\n", err)
				continue
			}
			go agent.ServeAgent(a, c)
		}
	}()

	// Run until SIGTERM is received
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM, syscall.SIGINT)
	<-sigterm

	shuttingDown = true
	log.Println("Shutting down cleanly...")
}
