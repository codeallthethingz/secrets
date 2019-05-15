package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/codeallthethingz/secrets/model"
	"github.com/logrusorgru/aurora"
	"github.com/urfave/cli"
)

// RevokeService remove all access for this service
func RevokeService(c *cli.Context) error {
	serviceName, _, passphrase, secretsFile, err := check1or2Args(c, "service name", "")
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if _, ok := secretsFile.HasService(serviceName); !ok {
		fmt.Println(aurora.Green("revoked"))
		return nil
	}
	newServices := []*model.Service{}
	for _, service := range secretsFile.Services {
		if service.Name != serviceName {
			newServices = append(newServices, service)
		}
	}
	secretsFile.Services = newServices
	secrets := getAllSecretNames(secretsFile)
	removeServiceFromSecrets(serviceName, secrets, secretsFile)
	secretsFile.Save(passphrase)
	return nil
}

func getAllSecretNames(secretsFile *model.SecretsFile) string {
	response := ""
	for _, secret := range secretsFile.Secrets {
		response += secret.Name + ","
	}
	return response
}

// RemoveAccess remove this serice from accessing any secrets
func RemoveAccess(c *cli.Context) error {
	serviceName, secrets, passphrase, secretsFile, err := check1or2Args(c, "service name", "secrets")
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	if _, ok := secretsFile.HasService(serviceName); !ok {
		fmt.Println(aurora.Green("removed"))
		return nil
	}
	removeServiceFromSecrets(serviceName, secrets, secretsFile)
	err = secretsFile.Save(passphrase)
	if err != nil {
		return err
	}
	fmt.Println(aurora.Green("removed"))
	return nil
}

func removeServiceFromSecrets(serviceName string, secrets string, secretsFile *model.SecretsFile) {
	for _, secretName := range strings.Split(secrets, ",") {
		secretName = strings.TrimSpace(secretName)
		for _, secret := range secretsFile.Secrets {
			if secretName == secret.Name {
				newAccess := []string{}
				for _, access := range secret.Access {
					if access != serviceName {
						newAccess = append(newAccess, access)
					}
				}
				secret.Access = newAccess
			}
		}
	}
}

// AddAccess add an access token to a secret
func AddAccess(c *cli.Context) error {
	serviceName, secrets, passphrase, secretsFile, err := check1or2Args(c, "service name", "secrets")
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	generatedToken, err := generateRandomHexBytes(50)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if service, serviceExists := secretsFile.HasService(serviceName); serviceExists {
		generatedToken = service.Secret
	} else {
		secretsFile.Services = append(secretsFile.Services, &model.Service{
			Name:   serviceName,
			Secret: generatedToken,
		})
	}
	arrayOfSecrets := strings.Split(secrets, ",")
	for _, secretName := range arrayOfSecrets {
		secretName = strings.TrimSpace(secretName)
		i := secretsFile.IndexOfSecret(secretName)
		if i == -1 {
			return cli.NewExitError("could not find secret named: "+secretName, 1)
		}
		if !deriveContains(secretsFile.Secrets[i].Access, serviceName) {
			secretsFile.Secrets[i].Access = append(secretsFile.Secrets[i].Access, serviceName)
		}
	}
	err = secretsFile.Save(passphrase)
	if err != nil {
		return cli.NewExitError(err, 13)
	}
	fmt.Printf(aurora.Green("added access to %s for %s\n").String(), aurora.Blue(serviceName), aurora.BrightBlue(secrets))
	fmt.Println("Please use this token to access the secrets serice through the api")
	fmt.Println(aurora.Yellow(string(generatedToken)))
	return nil
}

// Passphrase change to a new passphrase
func Passphrase(c *cli.Context) error {
	newPassphrase, _, _, secretsFile, err := check1or2Args(c, "new passphrase", "")
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	secretsFile.Save(newPassphrase)
	fmt.Println(aurora.Green("changed passphrase"))
	return nil
}

// Remove a secret from the file secrets.json
func Remove(c *cli.Context) error {
	name, _, passphrase, secretsFile, err := check1or2Args(c, "secret name", "")
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	i := secretsFile.IndexOfSecret(name)
	if i == -1 {
		fmt.Println(aurora.Red("not found, so removed"))
		return nil
	}
	secretsFile.Secrets = append(secretsFile.Secrets[:i], secretsFile.Secrets[i+1:]...)
	secretsFile.Save(passphrase)
	fmt.Println(aurora.Green("removed"))
	return nil
}

func check1or2Args(c *cli.Context, arg1Name string, arg2Name string) (string, string, string, *model.SecretsFile, error) {
	passphrase := strings.TrimSpace(c.GlobalString("passphrase"))
	if len(passphrase) == 0 {
		return "", "", "", nil, fmt.Errorf("must specify --passphrase")
	}
	arg1, arg2 := "", ""
	if arg1Name != "" {
		arg1 = strings.TrimSpace(c.Args().Get(0))
		if len(arg1) == 0 {
			return "", "", "", nil, fmt.Errorf("must specify %s as first argument", arg1Name)
		}
	}
	if arg2Name != "" {
		arg2 = strings.TrimSpace(c.Args().Get(1))
		if len(arg2) == 0 {
			return "", "", "", nil, fmt.Errorf("must specify %s as second argument", arg2Name)
		}
	}
	file := c.GlobalString("secrets-file")
	if strings.TrimSpace(file) == "" {
		return "", "", "", nil, fmt.Errorf("Must set a value for --secrets-file if used")
	}
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return "", "", "", nil, err
	}

	return arg1, arg2, passphrase, secretsFile, nil
}

// Set add a secret to the file secrets.json
func Set(c *cli.Context) error {
	name, secret, passphrase, secretsFile, err := check1or2Args(c, "secret name", "secret value")
	if err != nil {
		return cli.NewExitError(err, 1)
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
	err = secretsFile.Save(passphrase)
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
	_, _, _, secretsFile, err := check1or2Args(c, "", "")
	if err != nil {
		return cli.NewExitError(err, 1)
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
	name, _, _, secretsFile, err := check1or2Args(c, "secret name", "")
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

func generateRandomHexBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b)), nil
}
