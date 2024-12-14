package main

import (
	"errors"
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
	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/stores"
)

const version = "1.0.0"

var storesDir = flag.String("dir", ".", "directory for storing persistent data")
var connectionLimit = flag.Int("maxConnections", 30, "maximal number of connections from a single host within 10 minutes")

func main() {
	log.Printf("Starting SiaSMB v%s...\n", version)

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

	server := newServer(l, bs)
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
	go func() {
		func() {
			for {
				select {
				case <-c:
					return
				case <-time.After(10 * time.Minute):
					server.mu.Lock()
					server.connectionCount = make(map[string]int)
					server.mu.Unlock()

					server.bs.Mu.Lock()
					if err := server.bs.Save(); err != nil {
						log.Println("Couldn't save state:", err)
					}
					server.bs.Mu.Unlock()

					for _, cn := range server.connectionList {
						if cn.isStale() {
							server.closeConnection(cn)
						}
					}
				}
			}
		}()

		log.Println("Received interrupt signal, shutting down...")
		server.mu.Lock()
		defer server.mu.Unlock()
		server.enabled = false
		for addr, connection := range server.connectionList {
			log.Printf("Closing connection from client %s\n", addr)
			connection.conn.Close()
		}

		server.bs.Mu.Lock()
		if err := server.bs.Save(); err != nil {
			log.Println("Couldn't save state:", err)
		}
		server.bs.Mu.Unlock()

		l.Close()
		os.Exit(0)
	}()

	for {
		if conn, err := l.Accept(); err != nil {
			log.Println(err)
		} else {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if _, banned := server.bs.Bans[host]; banned {
				conn.Close()
				continue
			}

			server.mu.Lock()
			num := server.connectionCount[host]
			server.connectionCount[host] = num + 1
			server.mu.Unlock()
			if num >= *connectionLimit {
				server.blockHost(host, "too many connections")
				log.Printf("Blocked host %s for too many connections (%d)\n", host, num)
			}

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
						if errors.Is(err, smb2.ErrWrongProtocol) {
							server.blockHost(host, "old protocol")
							log.Printf("Blocked host %s for using old protocol\n", host)
						}
						return
					}
				}
			}()
		}
	}
}
