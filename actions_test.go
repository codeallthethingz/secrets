package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"testing"

	"github.com/codeallthethingz/secrets/model"
	"github.com/kami-zh/go-capturer"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

const testSecretsFile = "secrets.test.json"
const testPassphrase = "testpassphrase"

func TestEdges(t *testing.T) {
	context := Setup(t, nil)
	context.GlobalSet("passphrase", "")
	functions2 := []func(*cli.Context) error{
		Set, AddAccess,
	}
	for _, function := range functions2 {
		require.Error(t, function(context))
		require.Error(t, Set(Setup(t, []string{})))
		require.Error(t, Set(Setup(t, []string{"secretname"})))
	}
	functions1 := []func(*cli.Context) error{
		Get, Remove, RevokeAccess, Passphrase,
	}
	for _, function := range functions1 {
		require.Error(t, function(context))
		require.Error(t, Set(Setup(t, []string{})))
	}
	functions0 := []func(*cli.Context) error{
		List,
	}
	for _, function := range functions0 {
		require.Error(t, function(context))
	}
}
func TestRevokeAccess(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	accessContext := Setup(t, []string{"mynewservice", "secretname"})
	AddAccess(accessContext)
	err := RevokeAccess(accessContext)
	if err != nil {
		t.Fatal(err)
	}
	loadedSecretsFile, err := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 0, len(loadedSecretsFile.Services))
	require.Equal(t, 0, len(loadedSecretsFile.Secrets[0].Access))
}

func TestAddAccess(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	err := AddAccess(Setup(t, []string{"mynewservice", "secretname"}))

	if err != nil {
		t.Fatal(err)
	}

	loadedSecretsFile, err := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "mynewservice", loadedSecretsFile.Secrets[0].Access[0])
	require.Equal(t, 100, len(string(loadedSecretsFile.Services[0].Secret)))
}

func TestServiceNameAlreadyExists(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	accessContext := Setup(t, []string{"mynewservice", "secretname"})
	err := AddAccess(accessContext)
	if err != nil {
		t.Fatal(err)
	}
	err = AddAccess(accessContext)
	require.Error(t, err)
	require.Contains(t, err.Error(), "remove using revoke-access before adding", err.Error())
}

func TestGet(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}
	err = Get(context)
	require.Nil(t, err)

	out := capturer.CaptureStdout(func() { Get(context) })
	require.Contains(t, out, "secretvalue")
}

func TestRemove(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}
	removeContext := Setup(t, []string{"secretname"})
	err = Remove(removeContext)
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(testSecretsFile)
	if err != nil {
		t.Fatal(err)
	}
	require.NotContains(t, string(file), "secretname")
}

func TestList(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}
	out := capturer.CaptureStdout(func() { List(context) })
	require.Contains(t, out, "secretname")
}

func TestBadPassword(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	context.GlobalSet("passphrase", "nottherightpassword")
	require.Contains(t, Set(context).Error(), "message authentication failed")
}

func TestChangePassphrase(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	changedPassphraseContext := Setup(t, []string{"nottherightpassword"})
	err := Passphrase(changedPassphraseContext)
	if err != nil {
		t.Fatal(err)
	}
	require.Contains(t, Set(context).Error(), "message authentication failed")
	context.GlobalSet("passphrase", "nottherightpassword")
	err = Set(context)
	require.Nil(t, err)
}

func TestSetSecret(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}

	secretContents, err := ioutil.ReadFile(testSecretsFile)
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

	loadedSecretsFile, err := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "secretvalue", string(loadedSecretsFile.Secrets[0].Secret))
}
func TestSetWithAccess(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	defer Teardown()
	Set(context)
	AddAccess(Setup(t, []string{"org", "secretname"}))
	Set(context)
	secretContents, _ := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)

	require.Equal(t, 1, len(secretContents.Secrets[0].Access))
}

func Teardown() {
	os.Remove(testSecretsFile)
}

func Setup(t *testing.T, commandLine []string) *cli.Context {
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
	require.Equal(t, 2, len(allFlags), allFlags)
	set := flag.NewFlagSet("", 0)
	set.String("passphrase", testPassphrase, "")
	set.String("secrets-file", testSecretsFile, "")
	if commandLine != nil {
		set.Parse(commandLine)
	}
	context := cli.NewContext(app, set, nil)
	return context
}
