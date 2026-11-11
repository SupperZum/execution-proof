package managementrelay

import (
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const FixedConfigPath = "/onb17/management/relay.json"
const FDHintVariable = "ONB17_MANAGEMENT_TLS_FDS"
const ReadyFDHintVariable = "ONB17_MANAGEMENT_READY_FD"

// StartupReadiness owns a private write-only FIFO descriptor. Its contents are
// operational readiness, never proof or management authentication authority.
type StartupReadiness struct{ file *os.File }

func ParseReadyFDHint(hint string) (int, error) {
	if len(hint) < 3 || len(hint) > 4 {
		return 0, ErrConfiguration
	}
	fd, err := strconv.Atoi(hint)
	if err != nil || fd < 128 || fd > 4095 || strconv.Itoa(fd) != hint {
		return 0, ErrConfiguration
	}
	return fd, nil
}

// LoadStartupReadiness consumes only a reserved pipe alias. It accepts no path,
// socket, regular file, read end, or bidirectional descriptor.
func LoadStartupReadiness(hint string) (*StartupReadiness, error) {
	fd, err := ParseReadyFDHint(hint)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "management-startup-ready")
	var st syscall.Stat_t
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO || errno != 0 || flags&syscall.O_ACCMODE != syscall.O_WRONLY {
		_ = file.Close()
		return nil, ErrConfiguration
	}
	return &StartupReadiness{file: file}, nil
}

func (r *StartupReadiness) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}

func (r *StartupReadiness) signal() error {
	n, err := r.file.Write([]byte{'R'})
	closeErr := r.Close()
	if err != nil || n != 1 || closeErr != nil {
		return ErrServing
	}
	return nil
}

func owned(fd int, uid uint32, directory, readonly bool) error {
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&0022 != 0 {
		return ErrConfiguration
	}
	if directory {
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return ErrConfiguration
		}
	} else if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return ErrConfiguration
	}
	if readonly {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(fd, &fs) != nil || fs.Flags&1 == 0 {
			return ErrConfiguration
		}
	}
	return nil
}
func readOwnedConfig(root int, uid uint32, readonly bool) ([]byte, error) {
	directory, err := syscall.Openat(root, "management", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer syscall.Close(directory)
	if owned(directory, uid, true, readonly) != nil {
		return nil, ErrConfiguration
	}
	fd, err := syscall.Openat(directory, "relay.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	file := os.NewFile(uintptr(fd), "management-config")
	defer file.Close()
	if owned(fd, uid, false, readonly) != nil {
		return nil, ErrConfiguration
	}
	wire, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil || len(wire) > MaxConfigBytes {
		return nil, ErrConfiguration
	}
	return wire, nil
}

// LoadFixedConfig accepts no CLI, environment, symlink, or mutable config path.
// RO filesystem/ownership checks add a local fence; the measured startup owner
// must independently authenticate the exact file against C/D before execution.
func LoadFixedConfig() (Config, error) {
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, ErrConfiguration
	}
	defer syscall.Close(root)
	if owned(root, 0, true, false) != nil {
		return Config{}, ErrConfiguration
	}
	verified, err := syscall.Openat(root, "onb17", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, ErrConfiguration
	}
	defer syscall.Close(verified)
	if owned(verified, 0, true, true) != nil {
		return Config{}, ErrConfiguration
	}
	wire, err := readOwnedConfig(verified, 0, true)
	if err != nil {
		return Config{}, err
	}
	return DecodeConfig(wire)
}
func readSealedFD(fd int, limit int) ([]byte, error) {
	file := os.NewFile(uintptr(fd), "management-credential")
	if file == nil {
		return nil, ErrCredentials
	}
	defer file.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size <= 0 || st.Size > int64(limit) {
		return nil, ErrCredentials
	}
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), 1034, 0)
	if errno != 0 || seals&15 != 15 {
		return nil, ErrCredentials
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return nil, ErrCredentials
	}
	// ReadAt ignores an inherited seek offset and cannot block on a pipe/device.
	data := make([]byte, int(st.Size))
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, ErrCredentials
	}
	return data, nil
}

// The hint locates already-owned immutable descriptors. It cannot select
// config, trust roots, a backend, or unchecked credential contents.
func ParseCredentialFDHint(hint string) ([3]int, error) {
	var result [3]int
	if len(hint) < 11 || len(hint) > 14 {
		return result, ErrCredentials
	}
	parts := strings.Split(hint, ":")
	if len(parts) != 3 {
		return result, ErrCredentials
	}
	for index, part := range parts {
		fd, err := strconv.Atoi(part)
		if err != nil || fd < 128 || fd > 4095 || strconv.Itoa(fd) != part {
			return [3]int{}, ErrCredentials
		}
		for _, old := range result[:index] {
			if old == fd {
				return [3]int{}, ErrCredentials
			}
		}
		result[index] = fd
	}
	return result, nil
}

// LoadStartupCredentials consumes the three hinted sealed read-only sources.
// Public pins and X509KeyPair are checked by New before any listener opens.
func LoadStartupCredentials(hint string) (Credentials, error) {
	fds, err := ParseCredentialFDHint(hint)
	if err != nil {
		return Credentials{}, err
	}
	return loadCredentialFDs(fds)
}

func loadCredentialFDs(fds [3]int) (Credentials, error) {
	ca, err := readSealedFD(fds[0], MaxCredentialBytes)
	if err != nil {
		_ = syscall.Close(fds[1])
		_ = syscall.Close(fds[2])
		return Credentials{}, ErrCredentials
	}
	cert, err := readSealedFD(fds[1], MaxCredentialBytes)
	if err != nil {
		_ = syscall.Close(fds[2])
		return Credentials{}, ErrCredentials
	}
	key, err := readSealedFD(fds[2], MaxKeyBytes)
	if err != nil {
		return Credentials{}, ErrCredentials
	}
	return Credentials{ClientCAPEM: ca, ServerCertPEM: cert, ServerKeyPEM: key}, nil
}
