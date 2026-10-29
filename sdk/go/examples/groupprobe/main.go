package main

import (
	"encoding/json"
	"fmt"
	"os"

	relay "github.com/JunWeiUp/common-relay/sdk/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: groupprobe config.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var c relay.GroupConfig
	var data map[string]json.RawMessage
	if err = json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		return err
	}
	g, err := relay.NewGroups(&c, true)
	if err != nil {
		return err
	}
	var action string
	_ = json.Unmarshal(data["group_action"], &action)
	var result any = map[string]any{}
	switch action {
	case "create":
		c.Group = ""
		if err = g.PrepareCreate("My devices", "Creator"); err == nil {
			err = g.Create()
		}
	case "join":
		var inv relay.GroupInvitation
		var link string
		_ = json.Unmarshal(data["invitation_link"], &link)
		if link != "" {
			inv, err = g.ResolveInvitation(link)
		} else {
			err = json.Unmarshal(data["invitation"], &inv)
		}
		if err == nil {
			err = g.Join(inv, c.Device)
		}
	case "finish":
		result, err = g.FinishJoin()
	case "invite":
		var mode string
		var compact bool
		_ = json.Unmarshal(data["invite_mode"], &mode)
		_ = json.Unmarshal(data["compact"], &compact)
		result, err = g.Invite(mode, compact)
	case "approve":
		var inv relay.GroupInvitation
		var request relay.GroupEntry
		if err = json.Unmarshal(data["invitation"], &inv); err == nil {
			err = json.Unmarshal(data["request"], &request)
		}
		if err == nil {
			err = g.Approve(inv, request, false)
		}
	case "remove":
		var id string
		_ = json.Unmarshal(data["remove"], &id)
		err = g.Remove(id)
	case "rename":
		err = g.Rename(c.Device, "Updated device")
	case "leave", "disband":
		if err = g.PrepareExit(action == "disband"); err == nil {
			err = g.Exit()
		}
	default:
		result, err = g.Refresh()
	}
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var updated map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &updated); err != nil {
		return err
	}
	for _, k := range []string{"url", "app", "group", "device", "secret_key", "token", "public_key", "trusted_peers", "group_entry", "pending_create", "pending_join", "pending_exit"} {
		delete(data, k)
	}
	for k, v := range updated {
		data[k] = v
	}
	data["result"], err = json.Marshal(result)
	if err != nil {
		return err
	}
	encoded, err = json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(os.Args[1], encoded, 0600)
}
