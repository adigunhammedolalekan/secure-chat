package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
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


// serverResponse models response from chat server
type serverResponse struct {
	// type of response; could be
	// 1. public_key_download - used when publicKey is downloaded from server
	// 2. chat_message - used when a new encrypted message is received
	Type string `json:"type"`
	// Data is the actual data received from server
	Data json.RawMessage `json:"data"`
}
// publicKeyDownloadResponse
type publicKeyDownloadResponse struct {
	Username string `json:"username"`
	PublicKey string `json:"public_key"`
}

type Payload struct {
	Cmd string `json:"cmd"`
	Data interface{} `json:"data"`
}

func (p *Payload) ToBytes() ([]byte, error) {
	return json.Marshal(p)
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
	// with their name
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
// 5. accept and process stdIn from the main goroutine until SIGINT
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
// to that other users can have access to it
func (c *chatClient) publishPublicKey() error {
	pubKey, err := publicKeyToString(c.keyPair.PublicKey)
	if err != nil {
		return err
	}
	type publishKeyPayload struct {
		User string `json:"user"`
		PublicKey string `json:"public_key"`
	}
	publish := &publishKeyPayload{
		User:      c.username,
		PublicKey: pubKey,
	}
	payload := &Payload{
		Cmd:  "register_key",
		Data: publish,
	}
	data, err := payload.ToBytes()
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	return nil
}

func (c *chatClient) readLoop() {
	for {
		buf := make([]byte, 512)
		_, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		srvResponse := &serverResponse{}
		if err := json.Unmarshal(buf[:], srvResponse); err != nil {
			continue
		}
		if srvResponse.Type == "public_key_download" {
			p := &publicKeyDownloadResponse{}
			if err := json.Unmarshal(srvResponse.Data, p); err != nil {
				continue
			}
			if err := c.savePublicKey(p.Username, p.PublicKey); err != nil {

			}
		}
		m, err := c.enc.Decrypt(buf[:], c.keyPair.PrivateKey)
		if err != nil {
			log.Println("failed to decrypt message! ", err)
			continue
		}
		log.Println("Received message ", string(m))
	}
}

func (c *chatClient) startReadingInputs() {
	log.Println("start reading input")
	select {}
}

func (c *chatClient) sendChatMessage(message string) error {
	pubKey, ok := c.users[c.friendName]
	if !ok {
		return errors.New("friend's public key not available; cannot encrypt message")
	}
	type chatPayload struct {
		Username string `json:"username"`
		Message []byte `json:"message"`
	}
	chipherText, err := c.enc.Encrypt([]byte(message), pubKey)
	if err != nil {
		return err
	}
	chat := &chatPayload{
		Username: c.friendName,
		Message: chipherText,
	}
	payload := &Payload{
		Cmd: "send_message",
		Data: chat,
	}
	data, err := payload.ToBytes()
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	return nil
}

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
		log.Println("failed to establish secure connection.")
	}
}