package main

import (
	"context"
	"errors"
	relay "github.com/SupperZum/execution-proof/integration/management-relay"
	"os"
	"os/signal"
	"syscall"
)

func run() error {
	if len(os.Args) != 1 {
		return relay.ErrConfiguration
	}
	if os.Getuid() != 1001 || os.Geteuid() != 1001 || os.Getgid() != 1001 || os.Getegid() != 1001 {
		return relay.ErrConfiguration
	}
	groups, err := os.Getgroups()
	if err != nil {
		return relay.ErrConfiguration
	}
	for _, gid := range groups {
		if gid != 1001 {
			return relay.ErrConfiguration
		}
	}
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		return relay.ErrConfiguration
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 0, 0); errno != 0 {
		return relay.ErrConfiguration
	}
	hint, present := os.LookupEnv(relay.FDHintVariable)
	if !present {
		return relay.ErrCredentials
	}
	if _, err := relay.ParseCredentialFDHint(hint); err != nil {
		return err
	}
	readyHint, present := os.LookupEnv(relay.ReadyFDHintVariable)
	if !present {
		return relay.ErrConfiguration
	}
	if _, err := relay.ParseReadyFDHint(readyHint); err != nil {
		return err
	}
	os.Clearenv()
	ready, err := relay.LoadStartupReadiness(readyHint)
	if err != nil {
		return err
	}
	defer ready.Close()
	config, err := relay.LoadFixedConfig()
	if err != nil {
		return err
	}
	credentials, err := relay.LoadStartupCredentials(hint)
	if err != nil {
		return err
	}
	server, err := relay.New(config, credentials)
	clear(credentials.ServerKeyPEM)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	err = server.RunReady(ctx, ready)
	cancel()
	<-joined
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
func main() {
	if run() != nil {
		_, _ = os.Stderr.WriteString("management relay startup or transport rejected\n")
		os.Exit(1)
	}
}
