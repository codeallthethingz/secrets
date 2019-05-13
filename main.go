package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := CreateApp()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// CreateApp sets up the command line options
func CreateApp() *cli.App {
	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Name = "secrets"
	app.EnableBashCompletion = true
	app.Usage = "json file-based secrets manager"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "passphrase, p",
			Usage: "the phrase to encrypt and decrypt the vault",
		},
		cli.StringFlag{
			Name:  "secrets-file, f",
			Value: "secrets.json",
			Usage: "change the file that is being used to store secrets",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "set",
			Usage:     "set a secret to the credential file, overwrites if exists but keeps access list",
			Action:    Set,
			ArgsUsage: "`secret name` `secret value`",
		},
		{
			Name:      "get",
			Usage:     "get a secret out of the secrets file",
			Action:    Get,
			ArgsUsage: "`secret name`",
		},
		{
			Name:      "list",
			Usage:     "list all the secrets in the credentials file",
			Action:    List,
			ArgsUsage: " ",
		},
		{
			Name:      "remove",
			Usage:     "remove a secret from the credential file",
			Action:    Remove,
			ArgsUsage: "`secret name`",
		},
		{
			Name:      "add-access",
			Usage:     "returns a new access token with access to specified secrets for a named service",
			ArgsUsage: "`service name` `secret1,secret2,...`",
			Action:    AddAccess,
		},
		{
			Name:      "revoke-access",
			Usage:     "create a new access token with access to specified secrets",
			Action:    RevokeAccess,
			ArgsUsage: "`service name`",
		},
		{
			Name:      "change-passphrase",
			Usage:     "change the passphrase to a new passphrase",
			Action:    Passphrase,
			ArgsUsage: "`new passphrase`",
		},
	}
	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelp(c)
		if c.Command.Action == nil {
			return cli.NewExitError("error: no command specified", 1)
		}
		return nil
	}
	return app
}
