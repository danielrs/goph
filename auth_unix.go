// Copyright 2020 Mohammed El Bahja. All rights reserved.
// Use of this source code is governed by a MIT license.

package goph

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Uses SSH agent as Auth method.
// Panics on error.
func UseAgent() Auth {
	sshAgent, err := TryUseAgent()
	if err != nil {
		panic(err)
	}
	return sshAgent
}

// Uses SSH agent as Auth method.
func TryUseAgent() (Auth, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("could not find ssh agent: %w", err)
	}
	return Auth{
		ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers),
	}, nil
}
