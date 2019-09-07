package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"secure-chat/types"
	"sync"
	"time"
)
// chatServer implements a secure, end-to-end encrypted chat service
type chatServer struct {
	address      string
	messageSize  int
	// user's publicKeys mapped to thier username or id
	publicKeys   map[string]string
	// connected users
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
// start a concurrent tcp chat server
func (s *chatServer) start() error {
	handle, err := net.Listen("tcp", s.address)
	if err != nil {
		return err
	}
	for {
		conn, err := handle.Accept()
		if err != nil {
			log.Println("[TCP]: error occurred while accepting conn: ", err)
			continue // don't quit; continue waiting for other connections
		}

		go s.process(conn)
	}
}

// process read and process messages from client/user
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
		m := &types.Message{}
		if err := types.GobDecode(buf[:], m); err != nil {
			log.Println("failed to decode gob data: ", err)
			continue
		}
		switch m.Cmd {
		case "connect":
			connect := &types.ConnectPayload{}
			if err := types.GobDecode(m.Data, connect); err != nil {
				log.Println("failed to convert data to ConnectPayload{}: ", err)
				continue
			}
			go func() {
				// wait for user to submit their publicKey if it is not yet available.
				// this is useful in a case whereby user1 wants to chat with user2 but user2
				// isn't connected yet or user2 has not publish their publicKey.
				// The loop will wait in a separate goroutine until user2 is connected and
				// submit their publicKey, the submitted publicKey will be sent to user1 immediately
				// so that encrypted chat can begin
				for {
					err := s.processConnectPayload(connect.User, conn)
					if err == nil {
						break
					}else {
						time.Sleep(300 * time.Millisecond)
					}
				}
			}()
		case "register_key":
			payload := &types.KeyPayload{}
			if err := types.GobDecode(m.Data, payload); err != nil {
				log.Println("failed to convert data to KeyPayload{} ", err)
				continue
			}
			s.registerKeyAndAccount(payload.User, payload.PublicKey, conn)
		case "send_message":
			mPayload := &types.ChatPayload{}
			if err := types.GobDecode(m.Data, mPayload); err != nil {
				log.Println("failed to convert data to MessagePayload{}: ", err)
				continue
			}
			if err := s.sendChatMessage(mPayload.Username, mPayload.Message); err != nil {
				log.Println("failed to send message to client: ", err)
			}
		default:
			/*no-op*/
		}
	}
}

func (s *chatServer) registerKeyAndAccount(account, publicKey string, conn net.Conn) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	log.Printf("registering public key and net.Conn for account: %s", account)
	s.publicKeys[account] = publicKey
	s.conns[account] = conn
}

// sendChatMessage send already encrypted chat message to `toAccount`
// the message will be decrypted with `toAccount` privateKey on arrival
func (s *chatServer) sendChatMessage(toAccount string, message []byte) error {
	s.mtx.Lock()
	conn, ok := s.conns[toAccount]
	s.mtx.Unlock()
	if !ok {
		return fmt.Errorf("client %s not found", toAccount)
	}
	log.Println("Routing message to ", toAccount)
	m := &types.ChatPayload{
		Username: "",
		Message: message,
	}
	chatData, err := types.GobEncode(m)
	if err != nil {
		return err
	}
	srvResponse := &types.ServerResponse{Type: "message"}
	srvResponse.Data = chatData
	data, err := types.GobEncode(srvResponse)
	if err != nil {
		return err
	}
	n, err := conn.Write(data)
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
	r := &types.PublicKeyDownloadResponse{
		Username:   account,
		PublicKey: pubKey,
	}
	responseData, err := types.GobEncode(r)
	if err != nil {
		return err
	}
	srvResponse := &types.ServerResponse{Type: "public_key_download", Data: responseData}
	buffer, err := types.GobEncode(srvResponse)
	if err != nil {
		return err
	}
	if _, err := conn.Write(buffer); err != nil {
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
