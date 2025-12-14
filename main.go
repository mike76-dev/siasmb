package main

import (
	"context"
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

const version = "2.1.0-alpha"

var storesDir = flag.String("dir", ".", "directory for storing persistent data")

var isIndexd bool // true if `indexd` mode is active

func main() {
	log.Printf("Starting SiaSMB v%s...\n", version)

	// Parse command-line args.
	flag.Parse()
	dir, err := filepath.Abs(*storesDir)
	if err != nil {
		panic(err)
	}

	// Read the config file.
	cfg, err := stores.ReadConfig(dir)
	if err != nil {
		panic(err)
	}

	if cfg.Mode == "indexd" {
		isIndexd = true
		panic("indexd mode not supported yet")
	} else if cfg.Mode != "renterd" {
		panic("invalid mode")
	}

	if len(cfg.Database.Password) < 4 {
		panic("database password too short")
	}

	// Create the global context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to the SQL database.
	db, err := stores.NewStore(ctx, cfg.Database)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Start listening on the SMB port 445.
	l, err := net.Listen("tcp", ":445")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening at %s ...\n", l.Addr())
	defer l.Close()

	// Start the SMB server.
	server := newServer(l, db)

	// Start a thread to watch for the stop signal.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		func() {
			for {
				select {
				case <-c:
					return
				case <-time.After(10 * time.Minute):
					// Reset the abuse protection.
					server.mu.Lock()
					server.connectionCount = make(map[string]int)
					server.mu.Unlock()

					// Drop unused connections.
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

		l.Close()
		os.Exit(0)
	}()

	for {
		if conn, err := l.Accept(); err != nil {
			log.Println(err)
		} else {
			// Check if the remote host is on the ban list.
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			banned, _, err := db.IsBanned(host)
			if err != nil {
				panic(err)
			} else if banned {
				conn.Close()
				continue
			}

			// Ban the remote host if it forms too many connections.
			server.mu.Lock()
			num := server.connectionCount[host]
			server.connectionCount[host] = num + 1
			server.mu.Unlock()
			if num >= cfg.MaxConnections {
				server.blockHost(host, "too many connections")
				log.Printf("Blocked host %s for too many connections (%d)\n", host, num)
			}

			// Start serving the connection.
			go func() {
				if !server.enabled {
					return
				}

				log.Println("Incoming connection from", conn.RemoteAddr())
				c := server.newConnection(conn)
				c.ntlmServer = ntlm.NewServer("SERVER", "", db)

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
							// Ban the remote host if it keeps sending SMB requests after receiving
							// an SMB2_NEGOTIATE response.
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
