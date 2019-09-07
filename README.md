### Secure-Chat

#### Running secure-chat

* Run server
  `go run server/server.go`
  
* Run client `go run client/client.go -username "bob" -friendName "alice"`

* Run another client to imitate `alice`: `go run client/client.go -username "alice" -friendName "bob"`

You can now send end-to-end encrypted messages.