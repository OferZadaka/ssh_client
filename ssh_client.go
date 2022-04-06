package ssh_client

import (
	"log"

	"github.com/melbahja/goph"
)

type Client struct {
	Name     string
	Password string
	User     string
	SshKey   string
}

func New(name string, user string, password string, sshKey string) Client {
	c := Client{
		Name:     name,
		Password: password,
		User:     user,
		SshKey:   sshKey,
	}

	return c
}

//function to connect to the server
func connect(c Client, cmd []string) []string {
	var out []byte
	var err error
	var outList []string
	var client *goph.Client

	if c.SshKey != "" {
		// Start new ssh connection with private key.
		auth, err := goph.Key(c.SshKey, "")
		if err != nil {
			log.Fatal(err)
		}
		client, err = goph.New(c.User, c.Name, auth)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Start new ssh connection with password
		client, err = goph.New(c.User, c.Name, goph.Password(c.Password))
		if err != nil {
			log.Fatal(err)
		}
	}
	// Defer closing the network connection.
	defer client.Close()

	// Execute your command and append to []string
	for _, line := range cmd {
		out, err = client.Run(line)
		outList = append(outList, string(out))
	}
	if err != nil {
		log.Fatal(err)
	}

	// Get your output as []string].
	return outList
}
