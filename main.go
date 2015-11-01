package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"golang.org/x/crypto/openpgp"
)

// An empty Keyring
type emptyKR struct {
}

func (kr emptyKR) KeysById(id uint64) []openpgp.Key {
	return nil
}

func (kr emptyKR) DecryptionKeys() []openpgp.Key {
	return nil
}

func (kr emptyKR) KeysByIdUsage(uint64, byte) []openpgp.Key {
	return nil
}

var (
	passphrase string
	filename   string
	cpuprofile string
)

func init() {
	flag.StringVar(&filename, "filename", "",
		"Filename. (Default is stdin if no filename is supplied)")
	flag.StringVar(&passphrase, "passphrase", "", "Passphrase")
	flag.StringVar(&cpuprofile, "cpuprofile", "",
		"Recoird CPU profile in this file")
}

func newPromptFunction() func([]openpgp.Key, bool) ([]byte, error) {
	first := true

	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			// We only support passhphrases for symmetrically
			// encrypted decryption keys
			return nil, errors.New("Decrypting private keys not supported")
		}

		if first {
			first = false
			return []byte(passphrase), nil
		}

		return nil, errors.New("Already called")

	}
}

func main() {
	flag.Parse()

	if cpuprofile != "" {
		profFD, err := os.Create(cpuprofile)
		if err != nil {
			log.Fatalf("Cpuprofile: os.Create(): %v", err)
		}

		pprof.StartCPUProfile(profFD)
		defer pprof.StopCPUProfile()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
		syscall.SIGPIPE)
	go func() {
		<-c

		if cpuprofile != "" {
			pprof.StopCPUProfile()
		}

		// In case we had a hang, we print the stack trace here.
		buf := make([]byte, 256*1024)
		n := runtime.Stack(buf, true)
		fmt.Fprintln(os.Stderr, string(buf[0:n]))

		os.Exit(1)
	}()

	var fd *os.File = os.Stdin
	var err error
	if filename != "" {
		fd, err = os.Open(filename)
		if err != nil {
			log.Fatalf("Input: os.Open(): %v", err)
		}
		defer fd.Close()
	}

	md, err := openpgp.ReadMessage(fd, emptyKR{}, newPromptFunction(), nil)
	if err != nil {
		log.Fatalf("openpgp.ReadMessage(): %v", err)
	}
	log.Println("openpgp.ReadMessage() returned without error")

	_, err = io.Copy(os.Stdout, md.UnverifiedBody)
	if err != nil {
		log.Fatalf("Reading unverified plain text: io.Copy(): %v", err)
	}

	// Check that any authentication code for the message was
	// verified successfully
	if md.SignatureError != nil {
		log.Fatalln("Integrity Check FAILED:", md.SignatureError)
	}
}
