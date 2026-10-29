//go:build !unix && !windows

package relay

import (
	"errors"
	"os"
)

func lockJournalFile(*os.File) error {
	return errors.New("journal ownership locking is unsupported on this platform")
}
func unlockJournalFile(*os.File) {}
func syncDir(string) error       { return nil }
