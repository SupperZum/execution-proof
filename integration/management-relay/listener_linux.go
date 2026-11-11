package managementrelay

import (
	"net"
	"os"
	"syscall"
)

// Create the socket with its final bounded backlog, before it becomes reachable.
func boundedTCPListener(address string, backlog int) (*net.TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, ErrServing
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, ErrServing
	}
	file := os.NewFile(uintptr(fd), "management-listener")
	defer file.Close()
	var ip [4]byte
	copy(ip[:], addr.IP.To4())
	if syscall.Bind(fd, &syscall.SockaddrInet4{Port: addr.Port, Addr: ip}) != nil || syscall.Listen(fd, backlog) != nil {
		return nil, ErrServing
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, ErrServing
	}
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, ErrServing
	}
	return tcp, nil
}
