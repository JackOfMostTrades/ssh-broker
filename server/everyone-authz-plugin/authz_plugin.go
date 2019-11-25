package everyone_authz_plugin

import (
	"crypto/x509"
	"github.com/jackofmosttrades/ssh-broker/server/ssh-broker-plugin"
)

type EveryoneAuthzPlugin struct{}

func (*EveryoneAuthzPlugin) Name() string {
	return "everyone"
}

func (*EveryoneAuthzPlugin) Type() ssh_broker_plugin.PluginType {
	return ssh_broker_plugin.PluginType_AUTHZ
}

func (*EveryoneAuthzPlugin) IsAuthorized(clientCert *x509.Certificate, keyName string, metadata map[string]interface{}) (bool, error) {
	return true, nil
}

func LoadPlugin() ssh_broker_plugin.SshBrokerPlugin {
	return &EveryoneAuthzPlugin{}
}
