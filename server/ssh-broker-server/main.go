package main

import (
	"github.com/jackofmosttrades/ssh-broker/server"
	"github.com/jackofmosttrades/ssh-broker/server/email-whitelist-authz-plugin"
	"github.com/jackofmosttrades/ssh-broker/server/everyone-authz-plugin"
	"os"
)

func main() {
	server.MainWithPlugins(os.Args[1:],
		everyone_authz_plugin.LoadPlugin(),
		email_whitelist_authz_plugin.LoadPlugin())
}
