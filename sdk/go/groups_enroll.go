package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func (g *Groups) invitationGrant(inv GroupInvitation) (GroupGrant, error) {
	var gr GroupGrant
	if inv.Grant == nil || groupDecode(*inv.Grant, payloadGrantSchema, &gr) != nil {
		return gr, groupErr()
	}
	checked, err := groupGrant(inv.Grant, inv.Manager, GroupState{App: g.Config.App, Group: g.Config.Group, Revision: gr.AnchorRevision})
	if err != nil {
		return gr, err
	}
	key, err := decodeKey(inv.DelegateSecret)
	if err != nil || gr.Invitation != inv.ID || gr.Expires != inv.Expires || gr.SecretHash != groupDigest([]byte(inv.Secret)) || gr.DelegateKey != hex.EncodeToString(groupSigningKey(key).Public().(ed25519.PublicKey)) {
		return gr, groupErr()
	}
	return checked, nil
}
func (g *Groups) Pending(inv GroupInvitation) (*GroupEntry, error) {
	var r struct {
		Request *GroupEntry `json:"request"`
	}
	if err := g.call("GET", "/group/invitations/"+inv.ID, nil, "", &r); err != nil {
		return nil, err
	}
	if r.Request != nil {
		var j GroupRequest
		if groupDecode(*r.Request, payloadRequestSchema, &j) != nil || groupVerify(*r.Request, j.Member.SigningKey) != nil || j.Invitation != inv.ID || j.App != g.Config.App || j.Group != g.Config.Group || r.Request.Signer != j.Member.Device {
			return nil, groupErr()
		}
	}
	return r.Request, nil
}
func (g *Groups) Join(inv GroupInvitation, name string) error {
	c := g.Config
	if inv.Version != 1 || inv.Expires <= time.Now().Unix() || inv.URL != c.URL || inv.App != c.App || inv.Group != c.Group || (inv.Mode != "" && inv.Mode != "manual" && inv.Mode != "auto") || !objectID.MatchString(inv.ID) {
		return errors.New("invalid invitation")
	}
	if inv.Mode == "auto" {
		if _, err := g.invitationGrant(inv); err != nil {
			return err
		}
	}
	if err := g.token(); err != nil {
		return err
	}
	m, err := g.own(name)
	if err != nil {
		return err
	}
	j := GroupRequest{Version: 1, App: c.App, Group: c.Group, Invitation: inv.ID, Member: m, TokenHash: groupDigest([]byte(c.Token))}
	var e GroupEntry
	if c.PendingJoin != nil && c.PendingJoin.Invitation.ID == inv.ID {
		e = c.PendingJoin.Request
	} else {
		e, err = groupSign(j, c.SecretKey, c.Device)
		if err != nil {
			return err
		}
	}
	c.PendingJoin = &GroupPendingJoin{Invitation: inv, Request: e}
	var result any
	return g.call("POST", "/enroll/"+inv.ID, e, "Invitation "+inv.Secret, &result)
}
func (g *Groups) FinishJoin() (bool, error) {
	p := g.Config.PendingJoin
	if p == nil {
		return false, errors.New("join not prepared")
	}
	var req GroupRequest
	if err := groupDecode(p.Request, payloadRequestSchema, &req); err != nil {
		return false, err
	}
	inv := p.Invitation
	if inv.Mode == "auto" {
		return g.finishAuto(p, req)
	}
	var r struct {
		Entry *GroupEntry `json:"entry"`
	}
	if err := g.call("GET", "/enroll/"+inv.ID, nil, "Claim "+g.Config.Token, &r); err != nil {
		return false, err
	}
	if r.Entry == nil {
		return false, nil
	}
	e := *r.Entry
	s, err := groupState(e)
	if err != nil || e.Authorization != nil || groupVerify(e, inv.Manager.SigningKey) != nil || s.App != g.Config.App || s.Group != g.Config.Group {
		return false, groupErr()
	}
	own, ok := groupMember(s, g.Config.Device)
	expected := req.Member
	expected.Manager = own.Manager
	b, _ := groupBytes(p.Request)
	if !ok || e.Signer != inv.Manager.Device || s.Invitation != inv.ID || s.RequestHash != groupDigest(b) || own != expected {
		return false, groupErr()
	}
	if err = g.accept(e); err != nil {
		return false, err
	}
	g.Config.PendingJoin = nil
	return true, nil
}
func (g *Groups) finishAuto(p *GroupPendingJoin, req GroupRequest) (bool, error) {
	inv := p.Invitation
	grant, err := g.invitationGrant(inv)
	if err != nil {
		return false, err
	}
	after := grant.AnchorRevision - 1
	var current *GroupEntry
	var result struct {
		Revision int          `json:"revision"`
		Entries  []GroupEntry `json:"entries"`
		Entry    *GroupEntry  `json:"entry"`
	}
	for {
		result.Entries = nil
		if err = g.call("GET", "/enroll/"+inv.ID+"/auto?after="+strconv.Itoa(after), nil, "Claim "+g.Config.Token, &result); err != nil {
			return false, err
		}
		if result.Revision < grant.AnchorRevision || result.Revision > 4096 || len(result.Entries) == 0 {
			return false, groupErr()
		}
		for _, e := range result.Entries {
			if current == nil {
				b, er := groupBytes(e)
				s, es := groupState(e)
				if er != nil || es != nil || groupDigest(b) != grant.AnchorHash || s.Revision != grant.AnchorRevision || s.App != g.Config.App || s.Group != g.Config.Group {
					return false, groupErr()
				}
			} else if err = VerifyGroupAdvance(*current, e); err != nil {
				return false, err
			}
			x := e
			current = &x
		}
		s, er := groupState(*current)
		if er != nil || s.Revision <= after || s.Revision > result.Revision {
			return false, groupErr()
		}
		after = s.Revision
		if after == result.Revision {
			break
		}
	}
	var e GroupEntry
	if result.Entry != nil {
		if !reflect.DeepEqual(*current, *result.Entry) {
			return false, groupErr()
		}
		e = *current
	} else {
		s, _ := groupState(*current)
		s.Members = append(s.Members, req.Member)
		s.Revision++
		b, _ := groupBytes(*current)
		s.Previous = groupDigest(b)
		s.Invitation = inv.ID
		b, _ = groupBytes(p.Request)
		s.RequestHash = groupDigest(b)
		e, err = groupSign(s, inv.DelegateSecret, inv.Manager.Device)
		if err != nil {
			return false, err
		}
		e.Authorization = inv.Grant
		if err = VerifyGroupAdvance(*current, e); err != nil {
			return false, err
		}
		p.AutoEntry = &e
		var response GroupEntry
		if err = g.call("POST", "/enroll/"+inv.ID+"/auto", e, "Claim "+g.Config.Token, &response); err != nil {
			return false, err
		}
		if !reflect.DeepEqual(response, e) {
			return false, groupErr()
		}
	}
	s, err := groupState(e)
	own, ok := groupMember(s, g.Config.Device)
	b, _ := groupBytes(p.Request)
	if err != nil || !ok || !reflect.DeepEqual(e.Authorization, inv.Grant) || s.Invitation != inv.ID || s.RequestHash != groupDigest(b) || own != req.Member {
		return false, groupErr()
	}
	if err = g.accept(e); err != nil {
		return false, err
	}
	g.Config.PendingJoin = nil
	return true, nil
}
func (g *Groups) Approve(inv GroupInvitation, request GroupEntry, manager bool) error {
	if _, err := g.Refresh(); err != nil {
		return err
	}
	var j GroupRequest
	if groupDecode(request, payloadRequestSchema, &j) != nil || groupVerify(request, j.Member.SigningKey) != nil || j.Invitation != inv.ID || j.App != g.Config.App || j.Group != g.Config.Group {
		return groupErr()
	}
	s, err := groupState(*g.Config.GroupEntry)
	if err != nil {
		return err
	}
	m := j.Member
	m.Manager = manager
	members := make([]GroupMember, 0, len(s.Members)+1)
	for _, v := range s.Members {
		if v.Device != m.Device {
			members = append(members, v)
		}
	}
	s.Members = append(members, m)
	s.Invitation = inv.ID
	b, _ := groupBytes(request)
	s.RequestHash = groupDigest(b)
	return g.change(s)
}
func (g *Groups) change(s GroupState) error {
	old := *g.Config.GroupEntry
	s.Revision++
	b, _ := groupBytes(old)
	s.Previous = groupDigest(b)
	e, err := groupSign(s, g.Config.SecretKey, g.Config.Device)
	if err != nil {
		return err
	}
	if err = VerifyGroupAdvance(old, e); err != nil {
		return err
	}
	var result any
	if err = g.call("PUT", "/group", e, "", &result); err != nil {
		return err
	}
	return g.accept(e)
}
func (g *Groups) Remove(device string) error {
	if device == g.Config.Device {
		return errors.New("use exit for yourself")
	}
	r, err := g.Refresh()
	if err != nil {
		return err
	}
	s := r.State
	members := []GroupMember{}
	for _, m := range s.Members {
		if m.Device != device {
			members = append(members, m)
		}
	}
	s.Members = members
	s.Invitation = ""
	s.RequestHash = ""
	return g.change(s)
}
func (g *Groups) Rename(device, name string) error {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 128 {
		return errors.New("invalid name")
	}
	r, err := g.Refresh()
	if err != nil {
		return err
	}
	s := r.State
	found := false
	for i := range s.Members {
		if s.Members[i].Device == device {
			found = true
			if s.Members[i].Name == name {
				return nil
			}
			s.Members[i].Name = name
		}
	}
	if !found {
		return errors.New("device not found")
	}
	s.Invitation = ""
	s.RequestHash = ""
	return g.change(s)
}
func (g *Groups) PrepareExit(disband bool) error {
	if g.Config.PendingExit != nil {
		return nil
	}
	r, err := g.Refresh()
	if err != nil {
		return err
	}
	old := *g.Config.GroupEntry
	s := r.State
	own, ok := groupMember(s, g.Config.Device)
	if !ok || disband && !own.Manager {
		return errors.New("manager permission required")
	}
	members := []GroupMember{}
	if !disband {
		for _, m := range s.Members {
			if m.Device != g.Config.Device {
				members = append(members, m)
			}
		}
	}
	s.Members = members
	if len(members) == 0 {
		s.Closed = true
	}
	s.Invitation = ""
	s.RequestHash = ""
	s.Revision++
	b, _ := groupBytes(old)
	s.Previous = groupDigest(b)
	e, err := groupSign(s, g.Config.SecretKey, g.Config.Device)
	if err != nil {
		return err
	}
	if err = VerifyGroupAdvance(old, e); err != nil {
		return err
	}
	g.Config.PendingExit = &e
	return nil
}
func (g *Groups) Exit() error {
	if g.Config.PendingExit == nil {
		return errors.New("exit not prepared")
	}
	e := *g.Config.PendingExit
	var out any
	if err := g.call("POST", "/group/exit", e, "", &out); err != nil {
		if strings.Contains(err.Error(), "(409)") {
			g.Config.PendingExit = nil
		}
		return err
	}
	if err := g.accept(e); err != nil {
		return err
	}
	g.Config.PendingExit = nil
	return nil
}
func (g *Groups) Cancel(inv GroupInvitation) error {
	var out any
	return g.call("DELETE", "/group/invitations/"+inv.ID, nil, "", &out)
}
