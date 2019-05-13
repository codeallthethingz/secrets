package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/codeallthethingz/secrets/model"
	"github.com/logrusorgru/aurora"
	"github.com/urfave/cli"
)

// RevokeAccess remove this serice from accessing any secrets
func RevokeAccess(c *cli.Context) error {
	serviceName, _, passphrase, err := check1or2Args(c, "service name", "")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	file := c.GlobalString("secrets-file")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	if !secretsFile.HasService(serviceName) {
		fmt.Println(aurora.Green("removed"))
		return nil
	}
	for _, secret := range secretsFile.Secrets {
		newAccess := []string{}
		for _, access := range secret.Access {
			if access != serviceName {
				newAccess = append(newAccess, access)
			}
		}
		secret.Access = newAccess
	}
	newServices := []*model.Service{}
	for _, service := range secretsFile.Services {

		if service.Name != serviceName {
			newServices = append(newServices, service)
		}
	}
	secretsFile.Services = newServices
	err = secretsFile.Save(file, passphrase)
	if err != nil {
		return err
	}
	fmt.Println(aurora.Green("removed"))
	return nil
}

// AddAccess add an access token to a secret
func AddAccess(c *cli.Context) error {

	serviceName, secrets, passphrase, err := check1or2Args(c, "service name", "secrets")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	file := c.GlobalString("secrets-file")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	if secretsFile.HasService(serviceName) {
		return fmt.Errorf("service name %s already present, remove using revoke-access before adding", serviceName)
	}
	generatedToken, err := generateRandomString(50)
	if err != nil {
		return cli.NewExitError(err, 12)
	}
	arrayOfSecrets := strings.Split(secrets, ",")
	for _, secretName := range arrayOfSecrets {
		i := secretsFile.IndexOfSecret(secretName)
		if i == -1 {
			return fmt.Errorf("could not find secret named: %s", secretName)
		}
		secretsFile.Secrets[i].Access = append(secretsFile.Secrets[i].Access, serviceName)
	}
	secretsFile.Services = append(secretsFile.Services, &model.Service{
		Name:   serviceName,
		Secret: []byte(generatedToken),
	})
	err = secretsFile.Save(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 13)
	}
	fmt.Printf(aurora.Green("added access to %s for %s\n").String(), aurora.Blue(serviceName), aurora.BrightBlue(secrets))
	fmt.Println("Please use this token to access the secrets serice through the api")
	fmt.Println(aurora.Yellow(generatedToken))
	return nil
}

// Passphrase change to a new passphrase
func Passphrase(c *cli.Context) error {
	newPassphrase, _, passphrase, err := check1or2Args(c, "new passphrase", "")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	file := c.GlobalString("secrets-file")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	secretsFile.Save(file, newPassphrase)
	fmt.Println(aurora.Green("changed passphrase"))
	return nil
}

// Remove a secret from the file secrets.json
func Remove(c *cli.Context) error {
	name, _, passphrase, err := check1or2Args(c, "secret name", "")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	file := c.GlobalString("secrets-file")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	i := secretsFile.IndexOfSecret(name)
	if i == -1 {
		fmt.Println(aurora.Red("not found"))
		return nil
	}
	secretsFile.Secrets = append(secretsFile.Secrets[:i], secretsFile.Secrets[i+1:]...)
	secretsFile.Save(file, passphrase)
	fmt.Println(aurora.Green("removed"))
	return nil
}

func check1or2Args(c *cli.Context, arg1Name string, arg2Name string) (string, string, string, error) {
	passphrase := strings.TrimSpace(c.GlobalString("passphrase"))
	if len(passphrase) == 0 {
		return "", "", "", fmt.Errorf("must specify --passphrase")
	}
	arg1, arg2 := "", ""
	if arg1Name != "" {
		arg1 = strings.TrimSpace(c.Args().Get(0))
		if len(arg1) == 0 {
			return "", "", "", fmt.Errorf("must specify %s as first argument", arg1Name)
		}
	}
	if arg2Name != "" {
		arg2 = strings.TrimSpace(c.Args().Get(1))
		if len(arg2) == 0 {
			return "", "", "", fmt.Errorf("must specify %s as second argument", arg2Name)
		}
	}

	return arg1, arg2, passphrase, nil
}

// Set add a secret to the file secrets.json
func Set(c *cli.Context) error {
	name, secret, passphrase, err := check1or2Args(c, "secret name", "secret value")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	file := c.GlobalString("secrets-file")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	i := secretsFile.IndexOfSecret(name)
	newSecret := model.Secret{
		Name:   name,
		Secret: []byte(secret),
	}
	if i == -1 {
		secretsFile.Secrets = append(secretsFile.Secrets, &newSecret)
	} else {
		access := secretsFile.Secrets[i].Access
		newSecret.Access = access
		secretsFile.Secrets[i] = &newSecret
	}
	err = secretsFile.Save(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 8)
	}
	if i == -1 {
		fmt.Println(aurora.Green("added secret"))
	} else {
		fmt.Println(aurora.Green("replaced secret"))
	}
	return nil
}

// List all the secrets.
func List(c *cli.Context) error {
	_, _, passphrase, err := check1or2Args(c, "", "")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	file := c.GlobalString("secrets-file")
	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println(aurora.White("empty"))
		return nil
	}
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	if len(secretsFile.Secrets) == 0 {
		fmt.Println(aurora.White("empty"))
		return nil
	}
	for _, secret := range secretsFile.Secrets {
		accessList := "accessible by [" + strings.Join(secret.Access, ",") + "]"
		truncatedSecret := "****" + string(secret.Secret[len(secret.Secret)-4:])
		fmt.Printf("%s: %s %s\n", aurora.White(secret.Name), aurora.Green(truncatedSecret), aurora.Blue(accessList))
	}
	return nil
}

// Get a secret value
func Get(c *cli.Context) error {
	name, _, passphrase, err := check1or2Args(c, "secret name", "")
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	file := c.GlobalString("secrets-file")
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return cli.NewExitError("no secrets file", 1)
	}
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if len(secretsFile.Secrets) == 0 {
		return cli.NewExitError("no Secrets", 1)
	}
	for _, secret := range secretsFile.Secrets {
		if secret.Name == name {
			fmt.Println(string(secret.Secret))
			return nil
		}
	}
	return cli.NewExitError("colud not find secret: "+name, 1)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
