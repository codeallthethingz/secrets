package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"testing"

	"github.com/codeallthethingz/secrets/model"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestRevokeAccess(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	Set(context)
	context.Set("service-name", "mynewservice")
	context.Set("secrets", "secretname")
	AddAccess(context)
	err := RevokeAccess(context)
	if err != nil {
		t.Fatal(err)
	}
	loadedSecretsFile, err := model.LoadOrCreateSecretsFile("secret.json", "testpassphrase")
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 0, len(loadedSecretsFile.Services))
	require.Equal(t, 0, len(loadedSecretsFile.Secrets[0].Access))
}
func TestAddAccess(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	Set(context)
	context.Set("service-name", "mynewservice")
	context.Set("secrets", "secretname")
	err := AddAccess(context)
	if err != nil {
		t.Fatal(err)
	}

	loadedSecretsFile, err := model.LoadOrCreateSecretsFile("secret.json", "testpassphrase")
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "mynewservice", loadedSecretsFile.Secrets[0].Access[0])
	require.Equal(t, 100, len(string(loadedSecretsFile.Services[0].Secret)))
}

func TestServiceNameAlreadyExists(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	Set(context)
	context.Set("service-name", "mynewservice")
	context.Set("secrets", "secretname")
	err := AddAccess(context)
	if err != nil {
		t.Fatal(err)
	}
	err = AddAccess(context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "remove using revoke-access before adding")
}

func TestRemove(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}
	err = Remove(context)
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile("secret.json")
	if err != nil {
		t.Fatal(err)
	}
	require.NotContains(t, string(file), "secretname")
}

func TestBadPassword(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	Set(context)
	context.GlobalSet("passphrase", "nottherightpassword")
	require.Contains(t, Set(context).Error(), "message authentication failed")
}

func TestChangePassphrase(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	Set(context)
	context.GlobalSet("new-passphrase", "nottherightpassword")
	err := Passphrase(context)
	if err != nil {
		t.Fatal(err)
	}
	require.Contains(t, Set(context).Error(), "message authentication failed")

	context.Set("passphrase", "nottherightpassword")
	require.Nil(t, Set(context))
}

func TestSetSecret(t *testing.T) {
	context := Setup(t)
	defer Teardown(context)
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}

	secretContents, err := ioutil.ReadFile("secret.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(model.SecretsFile{
		Secrets: []*model.Secret{
			&model.Secret{
				Name:   "secretname",
				Secret: []byte("secretvalue"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Contains(t, string(secretContents), "secretname")
	require.NotContains(t, string(secretContents), "secretvalue")
	require.NotContains(t, string(secretContents), []byte("secretvalue"))
	require.NotEqual(t, string(data), string(secretContents), "Seems like the secret wasn't encrypted")

	loadedSecretsFile, err := model.LoadOrCreateSecretsFile("secret.json", "testpassphrase")
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "secretvalue", string(loadedSecretsFile.Secrets[0].Secret))
}

func Teardown(c *cli.Context) {
	os.Remove(c.GlobalString("secret-file"))
}

func Setup(t *testing.T) *cli.Context {
	app := CreateApp()
	var allFlags []cli.Flag
	for _, flag := range app.Flags {
		allFlags = append(allFlags, flag)
	}
	for _, command := range app.Commands {
		for _, flag := range command.Flags {
			allFlags = append(allFlags, flag)
		}
	}
	// check and balance to remind you to add any flags that will be used in tests here
	require.Equal(t, 9, len(allFlags), allFlags)
	set := flag.NewFlagSet("", 0)
	set.String("name", "", "")
	set.String("secret", "", "")
	set.String("passphrase", "", "")
	set.String("new-passphrase", "", "")
	set.String("secret-file", "", "")
	set.String("service-name", "", "")
	set.String("secrets", "", "")
	context := cli.NewContext(app, set, nil)
	context.Set("passphrase", "testpassphrase")
	context.Set("secret-file", "secret.json")
	context.Set("name", "secretname")
	context.Set("secret", "secretvalue")
	return context
}
