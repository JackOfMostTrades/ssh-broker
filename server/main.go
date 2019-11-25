package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jackofmosttrades/ssh-broker/common"
	"github.com/jackofmosttrades/ssh-broker/server/ssh-broker-plugin"
	"io/ioutil"
	"net/http"
	"os"
)

type httpError struct {
	message string
	code    int
}

func (e *httpError) Error() string {
	return e.message
}

// callerKey is a context key which is associated with the leaf client *x509.Certificate of the caller
type callerKey struct{}

func doRequest(writer http.ResponseWriter, request *http.Request, reqBody interface{}, handler func(context.Context, interface{}) (interface{}, error)) {
	if request.Method != http.MethodPost {
		http.Error(writer, "invalid method for this endpoint", http.StatusBadRequest)
		return
	}
	err := json.NewDecoder(request.Body).Decode(reqBody)
	if err != nil {
		http.Error(writer, fmt.Sprintf("unable to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	ctx := request.Context()
	if len(request.TLS.PeerCertificates) > 0 {
		ctx = context.WithValue(ctx, callerKey{}, request.TLS.PeerCertificates[0])
	}

	response, err := handler(ctx, reqBody)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			http.Error(writer, httpErr.message, httpErr.code)
			return
		}
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	writer.Header().Add("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(response)
}

func startServer(service common.SshBroker, listenAddr string, tlsConfig *tls.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/REST/v1/sign", func(writer http.ResponseWriter, request *http.Request) {

		doRequest(writer, request, new(common.SignRequest), func(ctx context.Context, r interface{}) (interface{}, error) {
			return service.Sign(ctx, r.(*common.SignRequest))
		})
	})
	mux.HandleFunc("/REST/v1/listKeys", func(writer http.ResponseWriter, request *http.Request) {
		doRequest(writer, request, new(common.ListKeysRequest), func(ctx context.Context, r interface{}) (interface{}, error) {
			return service.ListKeys(ctx, r.(*common.ListKeysRequest))
		})
	})

	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	http.Serve(listener, mux)

	return nil
}

func Main(args []string) {
	MainWithPlugins(args)
}

func MainWithPlugins(args []string, plugins ...ssh_broker_plugin.SshBrokerPlugin) {
	flagSet := flag.NewFlagSet("ssh-broker-server", flag.ContinueOnError)
	certPath := flagSet.String("cert", "", "Path to server certificate")
	keyPath := flagSet.String("key", "", "Path to server key")
	caCertPath := flagSet.String("caCert", "", "Path to CA certificate file for client certs.")
	authzPluginName := flagSet.String("authzPlugin", "", "Name of the authorization plugin to use.")
	keyDataPath := flagSet.String("keyData", "", "Path to key data file.")
	listenAddr := flagSet.String("listen", "0.0.0.0:443", "Listen address/port")

	err := flagSet.Parse(args)
	if err != nil {
		panic(err)
	}

	if *certPath == "" || *keyPath == "" {
		fmt.Println("--cert and --key flags are required")
		os.Exit(1)
	}
	if *keyDataPath == "" {
		fmt.Println("--keyData flag is required")
		os.Exit(1)
	}

	serverCert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
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
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	keyData, err := LoadKeyDataFile(*keyDataPath)
	if err != nil {
		fmt.Printf("Unable to load key data from file: %v", err)
		os.Exit(1)
	}

	var authzPlugin ssh_broker_plugin.SshBrokerAuthzPlugin
	if *authzPluginName != "" {
		for _, p := range plugins {
			if p.Name() == *authzPluginName && p.Type() == ssh_broker_plugin.PluginType_AUTHZ {
				authzPlugin = p.(ssh_broker_plugin.SshBrokerAuthzPlugin)
				break
			}
		}
		if authzPlugin == nil {
			fmt.Printf("No authorization plugin named \"%s\" was found\n", *authzPluginName)
			os.Exit(1)
		}
	}

	var service common.SshBroker = &sshBrokerImpl{
		authzPlugin: authzPlugin,
		keyData:     keyData,
	}

	err = startServer(service, *listenAddr, tlsConfig)
	if err != nil {
		panic(err)
	}
}
