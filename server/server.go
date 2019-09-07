package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type message struct {
	Cmd  string          `json:"cmd"`
	Data json.RawMessage `json:"data"`
}

type serverResponse struct {
	Type string `json:"type"`
	Data interface{} `json:"data"`
}

type chatServer struct {
	address      string
	messageSize  int
	publicKeys   map[string]string
	conns        map[string]net.Conn
	writeTimeOut time.Time
	readTimeout  time.Time

	mtx sync.RWMutex
}

func newChatServer(addr string) *chatServer {
	s := &chatServer{address: addr}
	s.conns = make(map[string]net.Conn, 0)
	s.publicKeys = make(map[string]string, 0)
	s.writeTimeOut = time.Now().Add(10 * time.Second)
	s.readTimeout = time.Now().Add(10 * time.Second)
	s.messageSize = 1024
	return s
}

func (s *chatServer) start() error {
	handle, err := net.Listen("tcp", s.address)
	if err != nil {
		return err
	}
	for {
		conn, err := handle.Accept()
		if err != nil {
			log.Println("[TCP]: error occurred while accepting conn: ", err)
			continue // continue waiting for other connections
		}

		go s.process(conn)
	}
}

func (s *chatServer) process(conn net.Conn) {
	for {
		buf := make([]byte, s.messageSize)
		_, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Println("temporary connection issue: ", err)
			continue
		}

		m := &message{}
		if err := json.Unmarshal(buf[:], m); err != nil {
			log.Println("a malformed json data was sent: ignoring...")
			continue
		}
		if m.Cmd == "register_key" {
			type keyPayload struct {
				User      string `json:"user"`
				PublicKey string `json:"public_key"`
			}
			payload := &keyPayload{}
			if err := json.Unmarshal(m.Data, payload); err != nil {
				log.Println("failed to process key registration data: ", err)
				continue
			}
			s.registerKeyAndAccount(payload.User, payload.PublicKey, conn)
		} else if m.Cmd == "send_message" {
			type messagePayload struct {
				User    string `json:"user"`
				Message string `json:"message"`
			}
			mPayload := &messagePayload{}
			if err := json.Unmarshal(m.Data, mPayload); err != nil {
				log.Println("failed to process chat message: ", err)
				continue
			}
			if err := s.sendChatMessage(mPayload.User, mPayload.Message); err != nil {
				log.Println("failed to send message to client: ", err)
			}
		} else if m.Cmd == "connect" {
			type connectPayload struct {
				User string `json:"user"`
			}
			connect := &connectPayload{}
			if err := json.Unmarshal(m.Data, connect); err != nil {
				log.Println("failed to process connect payload: ", err)
				continue
			}
			if err := s.processConnectPayload(connect.User, conn); err != nil {
				log.Println("failed to process connect command ", err)
			}
		}
	}
}

func (s *chatServer) registerKeyAndAccount(account, publicKey string, conn net.Conn) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.publicKeys[account] = publicKey
	s.conns[account] = conn
}

func (s *chatServer) sendChatMessage(toAccount, message string) error {
	s.mtx.Lock()
	conn, ok := s.conns[toAccount]
	s.mtx.Unlock()

	if !ok {
		return fmt.Errorf("client %s not found", toAccount)
	}

	n, err := conn.Write([]byte(message))
	if err != nil {
		return err
	}
	log.Println("written message to client: count=", n)
	return nil
}

func (s *chatServer) processConnectPayload(account string, conn net.Conn) error {
	s.mtx.Lock()
	pubKey, ok := s.publicKeys[account]
	s.mtx.Unlock()

	if !ok {
		return fmt.Errorf("publicKey not registered for account %s", account)
	}
	type response struct {
		Account   string `json:"account"`
		PublicKey string `json:"public_key"`
	}
	r := &response{
		Account:   account,
		PublicKey: pubKey,
	}
	srvResponse := &serverResponse{Type: "pub_key_download", Data: r}
	data, err := json.Marshal(srvResponse)
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		log.Println("failed to pass publicKey data to client ", err)
		return err
	}
	return nil
}

func main() {
	addr := ":8007"
	s := newChatServer(addr)

	log.Println("secure chat server accepting connection at", addr)
	if err := s.start(); err != nil {
		log.Fatal("secure chat server failed: ", err)
	}
}
