package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/stores"
)

var storesDir = flag.String("dir", ".", "directory for storing persistent data")

func main() {
	flag.Parse()
	dir, err := filepath.Abs(*storesDir)
	if err != nil {
		panic(err)
	}

	as, err := stores.NewJSONAccountStore(dir)
	if err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", ":445")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening at %s ...\n", l.Addr())
	defer l.Close()

	server := newServer(l)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Received interrupt signal, shutting down...")
		server.mu.Lock()
		defer server.mu.Unlock()
		server.enabled = false
		for addr, connection := range server.connectionList {
			log.Printf("Closing connection from client %s\n", addr)
			connection.conn.Close()
		}
		l.Close()
		os.Exit(0)
	}()

	for {
		if conn, err := l.Accept(); err != nil {
			fmt.Println(err)
		} else {
			go func() {
				if !server.enabled {
					return
				}

				log.Println("Incoming connection from", conn.RemoteAddr())
				c := server.newConnection(conn)
				c.ntlmServer = ntlm.NewServer("SERVER", "", as)

				for {
					msg, err := readMessage(conn)
					if err != nil && strings.Contains(err.Error(), "EOF") {
						time.Sleep(time.Second)
						continue
					}
					if err != nil {
						server.closeConnection(c)
						return
					}

					server.mu.Lock()
					server.stats.bytesRcvd += uint64(len(msg))
					server.mu.Unlock()

					if err := c.acceptRequest(msg); err != nil {
						server.closeConnection(c)
						return
					}
				}
			}()
		}
	}
}
