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
	app.Name = "secret"
	app.EnableBashCompletion = true
	app.Usage = "secret manager for rpm"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "passphrase",
			Usage: "the phrase to encrypt and decrypt the vault",
		},
		cli.StringFlag{
			Name:  "secret-file",
			Value: "secret.json",
			Usage: "change the file that is being used to store secrets",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "add-access",
			Usage:  "returns a new access token with access to specified secrets for a named service",
			Action: AddAccess,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "service-name",
					Usage: "the name of this service",
				},
				cli.StringFlag{
					Name:  "secrets",
					Usage: "comma separated list of secret names to give access to",
				},
			},
		},
		{
			Name:   "revoke-access",
			Usage:  "create a new access token with access to specified secrets",
			Action: RevokeAccess,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "service-name",
					Usage: "the name of the service to revoke",
				},
			},
		},
		{
			Name:   "change-passphrase",
			Usage:  "change the passphrase to a new passphrase",
			Action: Passphrase,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "new-passphrase",
					Usage: "the new passphrase",
				},
			},
		},
		{
			Name:   "remove",
			Usage:  "remove a secret from the credential file",
			Action: Remove,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name",
					Usage: "the name of the secret to remove",
				},
			},
		}, {
			Name:   "set",
			Usage:  "set a secret to the credential file, overwrites if exists but keeps access list",
			Action: Set,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name",
					Usage: "the name of the secret",
				},
				cli.StringFlag{
					Name:  "secret",
					Usage: "the secret to encrypt and save",
				},
			},
		}, {
			Name:   "list",
			Usage:  "list all the secrets in the credentials file",
			Action: List,
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
