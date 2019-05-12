package model

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

var checksumPhrase = []byte("checksumToEnsureThatThePassPhraseIsAlwaysTheSame")

// SecretsFile holder of secrets
type SecretsFile struct {
	// TODO change to camel case for json as this is used in an API now.
	Secrets  []*Secret
	Checksum []byte
	Services []*Service
}

// Secret name/encrypted bytes/access list to this secret
type Secret struct {
	Name   string
	Secret []byte
	Access []string
}

// Service encrypted bytes for a service to access a secret
type Service struct {
	Name   string
	Secret []byte
}

// GenerateNewSecretsFile creates a new file with a checksum
func GenerateNewSecretsFile(file string, passphrase string) error {
	secretsFile := SecretsFile{
		Checksum: checksumPhrase,
	}
	err := secretsFile.Save(file, passphrase)
	if err != nil {
		return err
	}
	return nil
}

// LoadOrCreateSecretsFile loads secrets from disk and decrypts them
// returns an error if something goes wrong in the loading process
func LoadOrCreateSecretsFile(file string, passphrase string) (*SecretsFile, error) {
	fmt.Println("loading: " + file)
	if _, err := os.Stat(file); os.IsNotExist(err) {
		err = GenerateNewSecretsFile(file, passphrase)
		if err != nil {
			return nil, err
		}
	}
	secretsFile := &SecretsFile{}
	err := secretsFile.load(file, passphrase)
	if err != nil {
		return nil, err
	}
	return secretsFile, nil
}

func (s *SecretsFile) load(file string, passphrase string) error {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, s)
	if err != nil {
		return err
	}
	err = s.processSecrets(passphrase, decryptValue)
	if err != nil {
		return err
	}
	if string(s.Checksum) != string(checksumPhrase) {
		return fmt.Errorf("incorrect passphrase")
	}
	return nil
}

func (s *SecretsFile) processSecrets(passphrase string, crypt func([]byte, string) ([]byte, error)) error {
	newValue, err := crypt(s.Checksum, passphrase)
	if err != nil {
		return err
	}
	s.Checksum = newValue
	for _, secret := range s.Secrets {
		newValue, err := crypt(secret.Secret, passphrase)
		if err != nil {
			return err
		}
		secret.Secret = newValue
	}
	for _, service := range s.Services {
		newValue, err := crypt(service.Secret, passphrase)
		if err != nil {
			return err
		}
		service.Secret = newValue
	}
	return nil
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encryptValue(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (s *SecretsFile) decrypt(passphrase string) error {
	return nil
}

// Save save this secrets file to disk, encrypted using the passphrase
func (s *SecretsFile) Save(file string, passphrase string) error {
	err := s.processSecrets(passphrase, encryptValue)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		return err
	}
	ioutil.WriteFile(file, data, 0644)
	err = s.decrypt(passphrase)
	if err != nil {
		return err
	}
	return nil
}

// HasService returns true if the service name has access to any secret
func (s *SecretsFile) HasService(name string) bool {
	for _, service := range s.Services {
		if service.Name == name {
			return true
		}
	}
	return false
}

// IndexOfSecret find the indef of a secret in the array that matches name
func (s *SecretsFile) IndexOfSecret(name string) int {
	for i, secret := range s.Secrets {
		if secret.Name == name {
			return i
		}
	}
	return -1
}

func decryptValue(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
