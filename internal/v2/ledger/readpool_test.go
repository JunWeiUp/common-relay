package ledger

import (
	"testing"
	"time"
)

// trapReadPool makes setup point the read pool at the single writer connection.
var trapReadPool bool

// TestLedgerTxPathsNeverUseReadPool reruns the ledger's write flows (bootstrap,
// signed changes, concurrent approvals, invitations, auto admission, exit and
// disband, file create/upload/commit/collect) with the read pool aliased to the
// writer. A read issued through Store.RDB (or the writer pool) while a ledger
// transaction is open would then wait for the connection that transaction holds
// and deadlock; the watchdog turns that into a failure with all stacks.
func TestLedgerTxPathsNeverUseReadPool(t *testing.T) {
	trapReadPool = true
	defer func() { trapReadPool = false }()
	watchdog := time.AfterFunc(90*time.Second, func() {
		panic("ledger transaction path deadlocked on the read pool")
	})
	defer watchdog.Stop()
	for name, fn := range map[string]func(*testing.T){
		"permissions": TestGroupPermissionsConcurrentApprovalAndRevocation,
		"invitations": TestInvitationLinkAndAutoRoutesOverV2,
		"auto":        TestInviteGrantAndLinkCascadeWithInvitation,
		"create":      TestSelfServiceCreationBoundaries,
		"exit":        TestSignedExitAndDisband,
		"files":       TestFilesResumeIsolationCommitAndCleanup,
		"quota":       TestFileQuota,
		"concurrent":  TestSameFileConcurrentUploadCommitAndCollection,
	} {
		t.Run(name, fn)
	}
}
