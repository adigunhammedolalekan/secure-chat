package types

import (
	"bytes"
	"encoding/gob"
)

func init() {
	gob.Register(KeyPayload{})
	gob.Register(&ConnectPayload{})
	gob.Register(&PublishKeyPayload{})
	gob.Register(&MessagePayload{})
	gob.Register(&PublicKeyDownloadResponse{})
}

type Message struct {
	Cmd  string          `json:"cmd"`
	Data []byte `json:"data"`
}

type ServerResponse struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

type KeyPayload struct {
	User      string `json:"user"`
	PublicKey string `json:"public_key"`
}

type MessagePayload struct {
	User    string `json:"user"`
	Message string `json:"message"`
}

type ConnectPayload struct {
	User string `json:"user"`
}

// publicKeyDownloadResponse
type PublicKeyDownloadResponse struct {
	Username string `json:"username"`
	PublicKey string `json:"public_key"`
}

type PublishKeyPayload struct {
	User string `json:"user"`
	PublicKey string `json:"public_key"`
}

type ChatPayload struct {
	Username string `json:"user"`
	Message []byte `json:"message"`
}

func GobEncode(value interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := gob.NewEncoder(buffer)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func GobDecode(data []byte, i interface{}) error {
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	if err := decoder.Decode(i); err != nil {
		return err
	}
	return nil
}

