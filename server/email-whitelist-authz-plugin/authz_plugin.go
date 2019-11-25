package email_whitelist_authz_plugin

import (
	"crypto/x509"
	"github.com/jackofmosttrades/ssh-broker/server/ssh-broker-plugin"
)

type EmailWhitelistAuthzPlugin struct{}

func (*EmailWhitelistAuthzPlugin) Name() string {
	return "emailWhitelist"
}

func (*EmailWhitelistAuthzPlugin) Type() ssh_broker_plugin.PluginType {
	return ssh_broker_plugin.PluginType_AUTHZ
}

func (*EmailWhitelistAuthzPlugin) IsAuthorized(clientCert *x509.Certificate, keyName string, metadata map[string]interface{}) (bool, error) {
	if clientCert == nil {
		return false, nil
	}

	// Get list of whitelisted emails from metadata
	emailWhitelist := make(map[string]bool)
	if emailWhitelistAttr, ok := metadata["emailWhitelist"]; ok {
		if emailWhitelistSlice, ok := emailWhitelistAttr.([]interface{}); ok {
			for _, emailIface := range emailWhitelistSlice {
				if email, ok := emailIface.(string); ok {
					emailWhitelist[email] = true
				}
			}
		}
	}

	if len(emailWhitelist) == 0 {
		return false, nil
	}

	// Check if any email SAN from the client certificate matches the email whitelist
	for _, clientEmail := range clientCert.EmailAddresses {
		if _, ok := emailWhitelist[clientEmail]; ok {
			return true, nil
		}
	}

	return true, nil
}

func LoadPlugin() ssh_broker_plugin.SshBrokerPlugin {
	return &EmailWhitelistAuthzPlugin{}
}
