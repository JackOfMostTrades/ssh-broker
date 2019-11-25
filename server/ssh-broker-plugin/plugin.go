package ssh_broker_plugin

import "crypto/x509"

type PluginType string

const (
	PluginType_AUTHZ = "AUTHZ"
)

type SshBrokerPlugin interface {
	Name() string
	Type() PluginType
}

type SshBrokerAuthzPlugin interface {
	SshBrokerPlugin
	IsAuthorized(clientCert *x509.Certificate, keyName string, metadata map[string]interface{}) (bool, error)
}
