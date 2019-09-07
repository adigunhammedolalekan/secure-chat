package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"secure-chat/types"
	"strings"
	"sync"
	"time"
)

// Encryptor is an interface to encrypt and decrypt message data
// before sending over the connection.
type Encryptor interface {
	Encrypt(data []byte, pubKey *rsa.PublicKey) ([]byte, error)
	Decrypt(data []byte, privKey *rsa.PrivateKey) ([]byte, error)
	GenKeyPair() (*KeyPair, error)
}

// AsymmetricEncryptor implements Encryptor{} to provide
// asymmetric encryption implementation
type AsymmetricEncryptor struct {
	rsaKeySize int
}
// Encrypt encrypts []data with publicKey, the encrypted data can only be decrypted
// with this publicKey's privateKey
func (*AsymmetricEncryptor) Encrypt(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
}
// Decrypt decrypts []data using current user/client's private key
func (*AsymmetricEncryptor) Decrypt(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, data, nil)
}
// GenPair generates a pair of public-private key
func (enc *AsymmetricEncryptor) GenKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, enc.rsaKeySize)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}, nil
}

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey *rsa.PublicKey
}

type chatClient struct {
	// current user's name and friendName is the name of the friend
	// user is intended to chat securely with
	username, friendName string
	// records of friends publicKey mapped
	// with their name or id
	users                map[string]*rsa.PublicKey
	conn                 net.Conn
	enc                  Encryptor
	keyPair              *KeyPair

	// guards users
	mtx sync.RWMutex
}
// newChatClient creates a new chatClient with username and friendName
// passed from command-line
func newChatClient(username, friendName string) *chatClient {
	c := &chatClient{username: username, friendName: friendName}
	c.users = make(map[string]*rsa.PublicKey, 0)
	c.enc = &AsymmetricEncryptor{rsaKeySize: 2048}
	return c
}

// connect starts chat session; it follows these steps
// 1. connect to server on port :8007
// 2. generate public-private KeyPair to encrypt and decrypt chats
// 3. publish publicKey to the server so that other users
//    in the network can have access to it, this publicKey will be used
//    by other users to encrypt messages to `this` client
// 4. start message readLoop by reading from connection stream
// 5. accept and process stdIn from the main goroutine until input == -q
func (c *chatClient) connect() error {
	conn, err := net.Dial("tcp", ":8007")
	if err != nil {
		return err
	}
	keyPair, err := c.enc.GenKeyPair()
	if err != nil {
		return err
	}
	c.keyPair = keyPair
	c.conn = conn
	if err := c.publishPublicKey(); err != nil {
		return err
	}
	// read incoming messages
	go c.readLoop()
	// read user inputs; this blocks
	c.startReadingInputs()
	return nil
}

// publishPublicKey send publicKey to server
// so that other users can have access to it
func (c *chatClient) publishPublicKey() error {
	pubKey, err := publicKeyToString(c.keyPair.PublicKey)
	if err != nil {
		return err
	}
	publish := &types.PublishKeyPayload{
		User:      c.username,
		PublicKey: pubKey,
	}
	publishData, err := types.GobEncode(publish)
	if err != nil {
		return err
	}
	payload := &types.Message{
		Cmd:  "register_key",
		Data: publishData,
	}
	data, err := types.GobEncode(payload)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	// as for friend's publicKey from server. We cannot perform encrypted chat
	// without friends publicKey
	if err := c.sendDownloadPublicKeyCommand(); err != nil {
		return err
	}
	return nil
}
// sendDownloadPublicKeyCommand asks the chat server for friend's publicKey
// the response will be retrieved in chatClient{}.readLoop()
func (c *chatClient) sendDownloadPublicKeyCommand() error {
	// TODO: remove this
	time.Sleep(500)
	connectPayload := &types.ConnectPayload{User: c.friendName}
	data, err := types.GobEncode(connectPayload)
	if err != nil {
		return err
	}
	m := &types.Message{
		Cmd: "connect",
		Data: data,
	}
	message, err := types.GobEncode(m)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(message); err != nil {
		return err
	}
	return nil
}
// readLoop read messages from server
func (c *chatClient) readLoop() {
	for {
		buf := make([]byte, 2048)
		_, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		srvResponse := &types.ServerResponse{}
		if err := types.GobDecode(buf[:], srvResponse); err != nil {
			log.Println("failed to decode ServerResponse{}: ", err)
			continue
		}
		if srvResponse.Type == "public_key_download" {
			p := &types.PublicKeyDownloadResponse{}
			if err := types.GobDecode(srvResponse.Data, p); err != nil {
				log.Println("failed to convert data to PublicKeyDownloadResponse{}: ", err)
				continue
			}
			if err := c.savePublicKey(p.Username, p.PublicKey); err != nil {
				log.Println("failed to register public key for user: ", err)
			}
		}else if srvResponse.Type == "message" {
			message := &types.ChatPayload{}
			if err := types.GobDecode(srvResponse.Data, message); err != nil {
				log.Println("failed to convert data to MessagePayload{}: ", err)
				return
			}
			// decrypt received message with user's private key
			decrypted, err := c.enc.Decrypt(message.Message, c.keyPair.PrivateKey)
			if err != nil {
				log.Println("failed to decode message ", err)
				continue
			}
			log.Printf("%s: %s", c.friendName, string(decrypted))
		}
	}
}

// startReadingInputs reads and process user inputs from `Stdin`
func (c *chatClient) startReadingInputs() {
	log.Println("Enter -q to quit. \nInput your message >")
	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Try again: ")
			continue
		}
		if strings.TrimSpace(strings.ToLower(input)) == "-q" {
			log.Println("Thank you!")
			break
		}
		if err := c.sendChatMessage(input); err != nil {
			log.Println("Couldn't send that message: ", err)
		}
	}
}
// sendChatMessage sends a encrypted message to `friendName`
// `friendName` publicKey is used to encrypt the message before sending
// over the conn
func (c *chatClient) sendChatMessage(message string) error {
	pubKey, ok := c.users[c.friendName]
	if !ok {
		return errors.New("friend's public key not available; cannot encrypt message")
	}
	chipherText, err := c.enc.Encrypt([]byte(message), pubKey)
	if err != nil {
		return err
	}
	chat := &types.ChatPayload{
		Username: c.friendName,
		Message: chipherText,
	}
	chatData, err := types.GobEncode(chat)
	if err != nil {
		return err
	}
	payload := &types.Message{
		Cmd: "send_message",
		Data: chatData,
	}
	data, err := types.GobEncode(payload)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	return nil
}

// publicKeyToString returns string rep of a *rsa.PublicKey
func publicKeyToString(publicKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubBytes), nil
}
// convertStringToPublicKey converts string *rsa.PublicKey to
// a *rsa.PublicKey
func convertStringToPublicKey(pubKey string) (*rsa.PublicKey, error) {
	pub := []byte(pubKey)
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to convert string to *rsa.PublicKey")
	}
	return key, nil
}

// savePublicKey saves a user's publicKey; the saved publicKey will be used
// to encrypt outgoing messages to this user
func (c *chatClient) savePublicKey(username, publicKey string) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	pubKey, err := convertStringToPublicKey(publicKey)
	if err != nil {
		return err
	}
	log.Printf("Registering publicKey for user %s", username)
	c.users[username] = pubKey
	return nil
}

func main() {
	var username string
	var friendName string
	flag.StringVar(&username, "username", "", "client username")
	flag.StringVar(&friendName, "friendName", "", "client friend's username")
	flag.Parse()

	if username == "" || friendName == "" {
		log.Println("username and friendName required")
		os.Exit(1)
	}

	s := newChatClient(username, friendName)
	if err := s.connect(); err != nil {
		log.Println("failed to establish secure connection. ", err)
		os.Exit(1)
	}
}