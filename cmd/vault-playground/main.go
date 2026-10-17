package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

const sessionNotice = "Disposable: fresh random key; temporary bbolt database; removed on normal exit."

const commandHelp = `put TEXT  store TEXT as the greeting
get       read the greeting
reopen    close and reopen this session's database
help      show commands and session boundary
quit      exit (EOF also exits)
`

func main() {
	if err := run(os.Stdin, os.Stdout, ""); err != nil {
		// run has already finished cleanup; even failed diagnostics exit nonzero.
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type session struct {
	provider *demoProvider
	path     string
	db       *storage.Database
	vault    *storage.Vault
}

// tempParent selects only where a new command-owned directory is created.
// It is private test setup, never an existing database path or a CLI option.
func run(input io.Reader, output io.Writer, tempParent string) (err error) {
	s := session{provider: newDemoProvider()}
	var dir string
	defer func() {
		err = errors.Join(err, s.closeDatabase())
		clear(s.provider.secret)
		if dir != "" {
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("removing temporary data: %w", removeErr))
			}
		}
	}()
	// Recover propagation before cleanup joins its own errors to the result.
	defer err2.Handle(&err, "vault playground")

	try.T1(fmt.Fprintln(output, sessionNotice))("writing startup notice")
	dir = try.T1(os.MkdirTemp(tempParent, "vault-playground-"))("creating temporary directory")
	s.path = filepath.Join(dir, "vault.db")
	try.T1(rand.Read(s.provider.secret))("generating session key")
	s.db = try.T1(storage.OpenBolt(s.path))("opening database")
	p := s.provider
	try.T(s.db.CreateVault(context.Background(), p.vault, p.id, p))("creating vault")
	s.vault = try.T1(s.db.OpenVault(context.Background(), p.vault, p.id, p))("opening vault")
	try.T(s.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To1(tx.EnsureChild([]byte("notes")))
		return nil // No greeting is written during setup.
	}))("creating notes namespace")
	return s.loop(input, output)
}

func (s *session) closeDatabase() error {
	if s.db == nil {
		return nil
	}
	// Database.Close closes its remaining Vault handles before its engine.
	err := s.db.Close()
	s.db, s.vault = nil, nil
	if err != nil {
		return fmt.Errorf("closing database and vault: %w", err)
	}
	return nil
}

func (s *session) reopen() (err error) {
	defer err2.Handle(&err, "reopen")
	try.To(s.closeDatabase())
	s.db = try.T1(storage.OpenBolt(s.path))("opening database")
	p := s.provider // Preserve the secret, IDs, and shared counter.
	s.vault = try.T1(s.db.OpenVault(context.Background(), p.vault, p.id, p))("opening vault")
	return nil
}

func (s *session) loop(input io.Reader, output io.Writer) (err error) {
	defer err2.Handle(&err, nil)
	scanner := bufio.NewScanner(input)
	for {
		try.T1(fmt.Fprint(output, "> "))("writing prompt")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		command, text, separated := strings.Cut(line, " ")
		switch command {
		case "get", "reopen", "help", "quit":
			if separated {
				try.T1(fmt.Fprintf(output, "error: %s: takes no arguments\n", command))("writing error")
				continue
			}
		}
		switch command {
		case "put":
			if !separated {
				try.T1(fmt.Fprintln(output, "error: put: use put TEXT"))("writing error")
				continue
			}
			if putErr := putGreeting(s.vault, text); putErr != nil {
				try.T1(fmt.Fprintf(output, "error: %v\n", putErr))("writing error")
				continue
			}
			try.T1(fmt.Fprintln(output, "ok"))("writing put result")
		case "get":
			value, found, getErr := getGreeting(s.vault)
			if getErr != nil {
				try.T1(fmt.Fprintf(output, "error: %v\n", getErr))("writing error")
				continue
			}
			if !found {
				value = "not found"
			}
			try.T1(fmt.Fprintln(output, value))("writing get result")
		case "reopen":
			try.To(s.reopen())
			try.T1(fmt.Fprintln(output, "reopened"))("writing reopen result")
		case "help":
			try.T1(fmt.Fprint(output, commandHelp, sessionNotice, "\n"))("writing help")
		case "quit":
			try.T(scanner.Err())("reading input")
			return nil
		default:
			try.T1(fmt.Fprintf(output, "error: unknown command %q; use help\n", command))("writing error")
		}
	}
	try.T(scanner.Err())("reading input")
	return nil
}

func putGreeting(vault *storage.Vault, text string) (err error) {
	defer err2.Handle(&err, "put")
	return vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		notes := try.To1(tx.ChildForUpdate([]byte("notes")))
		return notes.Put([]byte("greeting"), []byte(text))
	})
}

func getGreeting(vault *storage.Vault) (text string, found bool, err error) {
	defer err2.Handle(&err, "get")
	err = vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		notes := try.To1(tx.Child([]byte("notes")))
		value, present := try.To2(notes.Get([]byte("greeting")))
		text, found = string(value), present
		return nil
	})
	return text, found, err
}
