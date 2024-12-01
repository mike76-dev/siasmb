package main

import (
	"flag"
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

	bs, err := stores.NewJSONBansStore(dir)
	if err != nil {
		panic(err)
	}

	as, err := stores.NewJSONAccountStore(dir)
	if err != nil {
		panic(err)
	}

	ss, err := stores.NewSharesStore(dir)
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
	for _, sh := range ss.Shares {
		cs := make(map[string]struct{})
		fs := make(map[string]uint32)
		for _, p := range sh.Policies {
			cs[p.Username] = struct{}{}
			fs[p.Username] = stores.FlagsFromAccessRights(p)
		}
		if err := server.registerShare(sh.Name, sh.ServerName, sh.Password, sh.Bucket, cs, fs, sh.Remark); err != nil {
			log.Printf("Error registering share %s: %v\n", sh.Name, err)
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	connections := make(map[string]int)
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
		for host, num := range connections {
			log.Printf("Host %s: %d connections\n", host, num)
		}
		os.Exit(0)
	}()

	for {
		if conn, err := l.Accept(); err != nil {
			log.Println(err)
		} else {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if _, banned := bs.Bans[host]; banned {
				conn.Close()
				continue
			}

			num := connections[host]
			connections[host] = num + 1
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
						time.Sleep(100 * time.Millisecond)
						continue
					}
					if err != nil {
						log.Println("Error reading message:", err)
						server.closeConnection(c)
						return
					}

					server.mu.Lock()
					server.stats.bytesRcvd += uint64(len(msg))
					server.mu.Unlock()

					if err := c.acceptRequest(msg); err != nil {
						log.Println("couldn't accept request:", err)
						server.closeConnection(c)
						return
					}
				}
			}()
		}
	}
}
