package main

import (
	"net"
)

func (s *server) blockHost(host, reason string) {
	s.bs.Mu.Lock()
	s.bs.Bans[host] = reason
	s.bs.Mu.Unlock()

	for addr, c := range s.connectionList {
		h, _, _ := net.SplitHostPort(addr)
		if h == host {
			s.closeConnection(c)
		}
	}
}
