//go:build unix

package relay

import (
	"errors"
	"os"
	"syscall"
)

// flock is per open file description, so a second Journal in the same process also fails.
func lockJournalFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrJournalLocked
	}
	return err
}

func unlockJournalFile(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// syncDir makes a rename durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
