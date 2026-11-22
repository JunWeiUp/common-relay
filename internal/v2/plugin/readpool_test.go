package plugin

import (
	"net/http"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
)

type stubPlugin struct{}

func (stubPlugin) ID() string                     { return "stub" }
func (stubPlugin) RequiredTrust() core.TrustLevel { return core.TrustStrictE2E }
func (stubPlugin) EdgeHandler(*Host) http.Handler { return http.NotFoundHandler() }

// TestSaveBindingNeverQueriesOutsideItsTx points the read pool at the single
// writer connection: any read that SaveBinding issued outside its transaction
// (through the reader or the writer pool) would wait for the connection the
// transaction holds and deadlock. Ordinary reads around it must still work.
func TestSaveBindingNeverQueriesOutsideItsTx(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateSpace("sp", "", core.TrustStrictE2E); err != nil {
		t.Fatal(err)
	}
	defer st.RDB.Close()
	st.RDB = st.DB // trap
	h := NewHost(st, nil)
	if err := h.Register(stubPlugin{}); err != nil {
		t.Fatal(err)
	}
	space := "sp"
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			if _, err := h.SaveBinding(BindingUpdate{PluginID: "stub", Mount: "m", SpaceID: &space, Config: map[string]any{"k": i}}); err != nil {
				done <- err
				return
			}
		}
		_, err := h.GetBinding("stub", "m")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SaveBinding deadlocked: a read inside its transaction left the tx")
	}
}
