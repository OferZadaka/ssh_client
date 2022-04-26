package ssh_client

import (
	"log"
	"net"

	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
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
func VerifyHost(host string, remote net.Addr, key ssh.PublicKey) error {

	//
	// If you want to connect to new hosts.
	// here your should check new connections public keys
	// if the key not trusted you shuld return an error
	//

	// hostFound: is host in known hosts file.
	// err: error if key not in known hosts file OR host in known hosts file but key changed!
	hostFound, err := goph.CheckKnownHost(host, remote, key, "")

	// Host in known hosts but key mismatch!
	// Maybe because of MAN IN THE MIDDLE ATTACK!
	if hostFound && err != nil {

		return err
	}

	// handshake because public key already exists.
	if hostFound && err == nil {

		return nil
	}

	// Add the new host to known hosts file.
	return goph.AddKnownHost(host, remote, key, "~/.ssh/known_hosts")
}

//function to connect to the server
func Connect(c Client, cmd []string) []string {
	var out []byte
	var err error
	var outList []string
	var client *goph.Client

	if c.SshKey != "" {
		// Start new ssh connection with private key.
		auth, err := goph.Key(c.SshKey, "")
		if err != nil {
			log.Println(err)
			outList = append(outList, err.Error()+" "+c.Name)
			return outList
		}
		client, err = goph.NewUnknown(c.User, c.Name, auth)
		if err != nil {
			log.Println(err)
			outList = append(outList, err.Error()+" "+c.Name)
			return outList
		}
	} else {
		// Start new ssh connection with password
		client, err = goph.NewUnknown(c.User, c.Name, goph.Password(c.Password))
		if err != nil {
			log.Println(err)
			outList = append(outList, err.Error()+" "+c.Name)
			return outList
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
		log.Println(err)
		outList = append(outList, "Error")
		return outList
	}

	// Get your output as []string].
	return outList
}
