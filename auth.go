// Copyright 2020 Mohammed El Bahja. All rights reserved.
// Use of this source code is governed by a MIT license.

package goph

import (
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

type Auth []ssh.AuthMethod

// Combines multiple Auth methods.
func CombineAuth(auths ...Auth) Auth {
	result := make([]ssh.AuthMethod, 0, len(auths))
	for _, auth := range auths {
		result = append(result, auth...)
	}
	return result
}

// Get auth method from raw password.
func Password(pass string) Auth {
	return Auth{
		ssh.Password(pass),
	}
}

// Get auth method from private key with or without passphrase.
// Panics on error.
func Key(prvFile string, passphrase string) Auth {
	keyAuth, err := TryKey(prvFile, passphrase)
	if err != nil {
		panic(err)
	}
	return keyAuth
}

// Get auth method from private key with or without passphrase.
func TryKey(prvFile string, passphrase string) (Auth, error) {

	signer, err := GetSigner(prvFile, passphrase)
	if err != nil {
		return nil, err
	}

	return Auth{
		ssh.PublicKeys(signer),
	}, nil
}

// Get private key signer.
func GetSigner(prvFile string, passphrase string) (ssh.Signer, error) {

	var (
		err    error
		signer ssh.Signer
	)

	privateKey, err := ioutil.ReadFile(prvFile)

	if err != nil {

		return nil, err

	} else if passphrase != "" {

		signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))

	} else {

		signer, err = ssh.ParsePrivateKey(privateKey)
	}

	return signer, err
}
