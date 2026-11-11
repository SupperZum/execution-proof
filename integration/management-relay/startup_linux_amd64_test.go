package managementrelay

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func memfd(t *testing.T, data []byte, seals uintptr) int {
	t.Helper()
	name := append([]byte("onb17-relay-test"), 0)
	fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(&name[0])), 3, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	n, err := syscall.Write(int(fd), data)
	if err != nil || n != len(data) {
		syscall.Close(int(fd))
		t.Fatal("memfd write failed")
	}
	if seals != 0 {
		_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, seals)
		if errno != 0 {
			syscall.Close(int(fd))
			t.Fatal(errno)
		}
	}
	readonly, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(int(fd)), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	syscall.Close(int(fd))
	if err != nil {
		t.Fatal(err)
	}
	return readonly
}
func TestSealedCredentialFDIsBoundedAndIgnoresSeekOffset(t *testing.T) {
	data := []byte("synthetic-memory-only-test-credential")
	fd := memfd(t, data, 15)
	syscall.Seek(fd, 9, 0)
	got, err := readSealedFD(fd, len(data))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("sealed read rejected")
	}
	fd = memfd(t, data, 0)
	if _, err := readSealedFD(fd, len(data)); err != ErrCredentials {
		t.Fatal("mutable credential accepted")
	}
	fd = memfd(t, data, 15)
	if _, err := readSealedFD(fd, len(data)-1); err != ErrCredentials {
		t.Fatal("oversized credential accepted")
	}
	var pipe [2]int
	if syscall.Pipe2(pipe[:], syscall.O_CLOEXEC) != nil {
		t.Fatal("pipe failed")
	}
	defer syscall.Close(pipe[1])
	if _, err := readSealedFD(pipe[0], 100); err != ErrCredentials {
		t.Fatal("pipe credential accepted")
	}
	for _, seals := range []uintptr{1, 3, 7, 13, 14} {
		fd := memfd(t, data, seals)
		if _, err := readSealedFD(fd, len(data)); err != ErrCredentials {
			t.Fatal("incomplete seal set accepted")
		}
	}
	readonly := memfd(t, data, 15)
	writable, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(readonly), syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	syscall.Close(readonly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSealedFD(writable, len(data)); err != ErrCredentials {
		t.Fatal("non-readonly descriptor accepted")
	}
}
func TestOwnedConfigRejectsSymlinksMutableFilesAndOversize(t *testing.T) {
	p := fixture(t)
	wire, _ := json.Marshal(p.config)
	for _, mode := range []string{"valid", "symlink-file", "symlink-dir", "writable", "oversize", "require-rofs"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			management := filepath.Join(dir, "management")
			if err := os.Mkdir(management, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(management, "relay.json")
			data := wire
			if mode == "oversize" {
				data = make([]byte, MaxConfigBytes+1)
			}
			if err := os.WriteFile(path, data, 0444); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "symlink-file":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "symlink-dir":
				os.Rename(management, management+".real")
				os.Symlink(management+".real", management)
			case "writable":
				os.Chmod(path, 0664)
			}
			fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(fd)
			got, err := readOwnedConfig(fd, uint32(os.Geteuid()), mode == "require-rofs")
			if mode == "valid" {
				if err != nil || !bytes.Equal(got, wire) {
					t.Fatal("owned config rejected")
				}
			} else if err != ErrConfiguration {
				t.Fatal("untrusted config file accepted")
			}
		})
	}
}
func TestInheritedFDHelper(t *testing.T) {
	if os.Getenv("ONB17_TEST_FD_HELPER") != "1" {
		return
	}
	var high [3]int
	for index, fd := range []int{3, 4, 5} {
		alias, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 128)
		if errno != 0 {
			t.Fatal(errno)
		}
		high[index] = int(alias)
	}
	for _, fd := range []int{3, 4, 5} {
		syscall.Close(fd)
	}
	hint := strconv.Itoa(high[0]) + ":" + strconv.Itoa(high[1]) + ":" + strconv.Itoa(high[2])
	credentials, err := LoadStartupCredentials(hint)
	if err != nil || string(credentials.ClientCAPEM) != "ca" || string(credentials.ServerCertPEM) != "cert" || string(credentials.ServerKeyPEM) != "key" {
		t.Fatal("inherited descriptor loading rejected")
	}
	for _, fd := range high {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF {
			t.Fatal("credential descriptor remained open")
		}
	}
}

func TestDescriptorHintCannotSelectTrustOrLowDescriptors(t *testing.T) {
	if fds, err := ParseCredentialFDHint("128:129:4095"); err != nil || fds != [3]int{128, 129, 4095} {
		t.Fatal("valid owned descriptor hint rejected")
	}
	for _, hint := range []string{"", "3:4:5", "127:128:129", "128:129:4096", "128:128:130", "0128:129:130", "128:129", "128:129:130:131", "128: 129:130", "128:+129:130", "/tmp/ca:129:130", "128:129:130\n", strings.Repeat("1", 10000) + ":129:130"} {
		if _, err := ParseCredentialFDHint(hint); err != ErrCredentials {
			t.Fatal("invalid descriptor hint accepted")
		}
	}
}
func TestFixedInheritedCredentialDescriptorOwnership(t *testing.T) {
	files := []*os.File{os.NewFile(uintptr(memfd(t, []byte("ca"), 15)), "test-ca"), os.NewFile(uintptr(memfd(t, []byte("cert"), 15)), "test-cert"), os.NewFile(uintptr(memfd(t, []byte("key"), 15)), "test-key")}
	for _, file := range files {
		defer file.Close()
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInheritedFDHelper$")
	cmd.Env = append(os.Environ(), "ONB17_TEST_FD_HELPER=1")
	cmd.ExtraFiles = files
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("inherited FD helper failed: %s", output)
	}
}

func TestHighFDExecHelper(t *testing.T) {
	if os.Getenv("ONB17_TEST_HIGH_FD_HELPER") != "1" {
		return
	}
	hint := os.Getenv(FDHintVariable)
	fds, err := ParseCredentialFDHint(hint)
	if err != nil {
		t.Fatal("invalid helper hint")
	}
	credentials, err := LoadStartupCredentials(hint)
	if err != nil || string(credentials.ClientCAPEM) != "ca" || string(credentials.ServerCertPEM) != "cert" || string(credentials.ServerKeyPEM) != "key" {
		t.Fatal("high alias inheritance failed")
	}
	for _, fd := range fds {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF {
			t.Fatal("high alias leaked")
		}
	}
}
func TestReservedHighAliasesSurviveExecWithoutDescriptorReplacement(t *testing.T) {
	var high [3]int
	for index, data := range [][]byte{[]byte("ca"), []byte("cert"), []byte("key")} {
		fd := memfd(t, data, 15)
		alias, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 128)
		syscall.Close(fd)
		if errno != 0 {
			t.Fatal(errno)
		}
		high[index] = int(alias)
		defer syscall.Close(int(alias))
	}
	// Test process only: production clears CLOEXEC on these reserved aliases in
	// the child's pre-exec hook, leaving the parent's descriptors untouched.
	for _, fd := range high {
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); errno != 0 {
			t.Fatal(errno)
		}
	}
	hint := strconv.Itoa(high[0]) + ":" + strconv.Itoa(high[1]) + ":" + strconv.Itoa(high[2])
	cmd := exec.Command(os.Args[0], "-test.run=^TestHighFDExecHelper$")
	cmd.Env = append(os.Environ(), "ONB17_TEST_HIGH_FD_HELPER=1", FDHintVariable+"="+hint)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reserved alias exec failed: %s", output)
	}
}
