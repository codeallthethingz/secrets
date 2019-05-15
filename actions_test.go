package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/codeallthethingz/secrets/model"
	"github.com/kami-zh/go-capturer"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

const testSecretsFile = "secrets.test.json"
const testPassphrase = "testpassphrase"

func TestMissingFileOrSecret(t *testing.T) {
	defer Teardown()
	context := Setup(t, []string{"secretnameMissing", "secretvalue"})
	Set(context)
	Remove(context)
	require.Contains(t, capturer.CaptureStdout(func() { Remove(context) }), "not found")
	require.Contains(t, capturer.CaptureStdout(func() { RevokeService(context) }), "revoked")
	require.Error(t, Get(context))
}

func TestEdges(t *testing.T) {
	context := Setup(t, nil)
	context.GlobalSet("passphrase", "")
	functions2 := []func(*cli.Context) error{
		Set, AddAccess, RemoveAccess,
	}
	for _, function := range functions2 {
		require.Error(t, function(context))
		require.Error(t, Set(Setup(t, []string{})))
		require.Error(t, Set(Setup(t, []string{"secretname"})))
		require.Error(t, Set(Setup(t, []string{"--secrets-file", " ", "secretname", "secret value"})))
	}
	functions1 := []func(*cli.Context) error{
		Get, Remove, RevokeService, Passphrase, GetAccessToken,
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
func TestRemoveAccess(t *testing.T) {
	defer Teardown()
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	Set(Setup(t, []string{"secretname2", "secretvalue"}))
	loadedSecretsFile, _ := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	require.Equal(t, 2, len(loadedSecretsFile.Secrets))
	AddAccess(Setup(t, []string{"mynewservice", "secretname, secretname2"}))
	AddAccess(Setup(t, []string{"mynewservice2", "secretname, secretname2"}))
	err := RemoveAccess(Setup(t, []string{"mynewservice", "secretname2"}))
	if err != nil {
		t.Fatal(err)
	}
	loadedSecretsFile, err = model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 2, len(loadedSecretsFile.Services))
	require.Equal(t, 2, len(loadedSecretsFile.Secrets[0].Access))
	require.Equal(t, "mynewservice", loadedSecretsFile.Secrets[0].Access[0])
	require.Equal(t, "mynewservice2", loadedSecretsFile.Secrets[0].Access[1])
	require.Equal(t, 1, len(loadedSecretsFile.Secrets[1].Access))
	require.Equal(t, "mynewservice2", loadedSecretsFile.Secrets[1].Access[0])
}
func TestRemoveAccessEdges(t *testing.T) {
	defer Teardown()
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	removeContext := Setup(t, []string{"mynewservice", "secretname2"})
	out := capturer.CaptureStdout(func() { RemoveAccess(removeContext) })
	require.Contains(t, out, "removed")
}
func TestGetAccessToken(t *testing.T) {
	defer Teardown()
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	generateAccessMessage := capturer.CaptureStdout(func() { AddAccess(Setup(t, []string{"myservice", "secretname"})) })
	accessMessage := capturer.CaptureStdout(func() { GetAccessToken(Setup(t, []string{"myservice", "secretname"})) })
	require.NotEmpty(t, accessMessage)
	require.Contains(t, generateAccessMessage, strings.TrimSpace(accessMessage))
}
func TestRevokeAccess(t *testing.T) {
	defer Teardown()
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	Set(Setup(t, []string{"secretname2", "secretvalue"}))
	AddAccess(Setup(t, []string{"mynewservice", "secretname, secretname2"}))
	AddAccess(Setup(t, []string{"mynewservice2", "secretname"}))
	err := RevokeService(Setup(t, []string{"mynewservice"}))
	if err != nil {
		t.Fatal(err)
	}
	loadedSecretsFile, err := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 1, len(loadedSecretsFile.Services))
	require.Equal(t, 2, len(loadedSecretsFile.Secrets))
	require.Equal(t, 1, len(loadedSecretsFile.Secrets[0].Access))
	require.Equal(t, "mynewservice2", loadedSecretsFile.Secrets[0].Access[0])
	require.Equal(t, 0, len(loadedSecretsFile.Secrets[1].Access))
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
func TestAddAccessMissingSecret(t *testing.T) {
	err := AddAccess(Setup(t, []string{"mynewservice", "secretname"}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not find secret named: secretname")
}

func TestListNoFile(t *testing.T) {
	out := capturer.CaptureStdout(func() { List(Setup(t, []string{"secretname", "secretvalue"})) })
	require.Contains(t, out, "empty")
}
func TestListNoSecrets(t *testing.T) {
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	err := Remove(Setup(t, []string{"secretname", "secretvalue"}))
	if err != nil {
		t.Error(err)
	}
	out := capturer.CaptureStdout(func() { List(Setup(t, []string{"secretname", "secretvalue"})) })
	require.Contains(t, out, "empty")
}

func TestAddAccessTwice(t *testing.T) {
	defer Teardown()
	Set(Setup(t, []string{"secretname", "secretvalue"}))
	AddAccess(Setup(t, []string{"mynewservice", "secretname"}))
	AddAccess(Setup(t, []string{"mynewservice", "secretname"}))
	loadedSecretsFile, err := model.LoadOrCreateSecretsFile(testSecretsFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	json, _ := json.Marshal(loadedSecretsFile)
	fmt.Println(string(json))
	require.Equal(t, 1, len(loadedSecretsFile.Services))
	require.Equal(t, 1, len(loadedSecretsFile.Secrets[0].Access))
}

func TestGet(t *testing.T) {
	context := Setup(t, []string{"secretname", "secretvalue"})
	missingContext := Setup(t, []string{"secretname2", "secretvalue"})
	defer Teardown()
	err := Set(context)
	if err != nil {
		t.Fatal(err)
	}
	err = Get(context)
	require.Nil(t, err)

	out := capturer.CaptureStdout(func() { Get(context) })
	require.Contains(t, out, "secretvalue")
	require.Error(t, Get(missingContext))
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
			{
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
