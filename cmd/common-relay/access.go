package main

import (
	"log"
	"strings"

	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
)

// resolveAccessHash picks the single active Relay-Access hash.
//
// The admin API stores rotations in the v2 settings table ("access_hash"), while
// operators keep --access-password-file on disk. To keep one source of truth:
//   - no DB value: the file is active;
//   - the file changed since the relay last adopted it ("access_file_seen"):
//     the operator edited it on purpose, so the file wins and is written to the DB;
//   - otherwise the DB value (an admin rotation) stays active.
//
// The first start after upgrading records the current file as seen without
// overriding an existing admin rotation.
func resolveAccessHash(st *v2core.Store, fileHex string) (hexHash, source string, updatedAt int64, err error) {
	fileHex = strings.ToLower(fileHex)
	dbHex, dbUpd, haveDB, err := st.GetSetting("access_hash")
	if err != nil {
		return "", "", 0, err
	}
	seen, _, haveSeen, err := st.GetSetting("access_file_seen")
	if err != nil {
		return "", "", 0, err
	}
	switch {
	case !haveDB || len(dbHex) != 64:
		if _, err := st.SetSetting("access_file_seen", fileHex); err != nil {
			return "", "", 0, err
		}
		return fileHex, "file", 0, nil
	case !haveSeen:
		if _, err := st.SetSetting("access_file_seen", fileHex); err != nil {
			return "", "", 0, err
		}
		return strings.ToLower(dbHex), "db", dbUpd, nil
	case seen != fileHex:
		log.Printf("access password file changed since last start; it now overrides the admin-set password")
		upd, err := st.SetSetting("access_hash", fileHex)
		if err != nil {
			return "", "", 0, err
		}
		if _, err := st.SetSetting("access_file_seen", fileHex); err != nil {
			return "", "", 0, err
		}
		return fileHex, "file", upd, nil
	default:
		return strings.ToLower(dbHex), "db", dbUpd, nil
	}
}
