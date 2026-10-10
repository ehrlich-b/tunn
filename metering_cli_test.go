package main

import (
	"errors"
	"flag"
	"testing"
	"time"
)

func TestMeteringCLIParsesBudgetsAndFlagPositions(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{"create", "api", "--for", "agent@example.com", "--expires", "1h", "--rate", "60", "--monthly-requests", "100", "--monthly-bytes", "4096", "--server", "https://127.0.0.1:8443", "--insecure"},
		{"create", "--for=agent@example.com", "--expires=1h", "--rate=60", "--monthly-requests=100", "--monthly-bytes=4096", "--server=https://127.0.0.1:8443", "--insecure", "api"},
	} {
		o, err := parseMeteringOptions("grant", args, now)
		if err != nil {
			t.Fatal(err)
		}
		if o.endpoint != "api" || o.consumer != "agent@example.com" || o.rate != 60 || o.requests != 100 || o.bytes != 4096 || !o.expires.Equal(now.Add(time.Hour)) || !o.insecure {
			t.Fatalf("options=%+v", o)
		}
	}
	o, err := parseMeteringOptions("usage", []string{"api", "--month", "2026-09"}, now)
	if err != nil || o.month != "2026-09" {
		t.Fatalf("usage=%+v %v", o, err)
	}
	o, err = parseMeteringOptions("grant", []string{"revoke", "api", "12345678-1234-1234-1234-123456789012"}, now)
	if err != nil || o.grantID == "" {
		t.Fatalf("revoke=%+v %v", o, err)
	}
	o, err = parseMeteringOptions("grant", []string{"create", "api", "--expires", "2026-10-11T12:00:00Z"}, now)
	if err != nil || !o.expires.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("absolute expiry=%+v %v", o, err)
	}
}
func TestMeteringCLIRejectsInvalidLimits(t *testing.T) {
	now := time.Now()
	for _, args := range [][]string{{}, {"unknown", "api"}, {"list", "../api"}, {"create"}, {"create", "../api"}, {"create", "api", "--expires=0s"}, {"create", "api", "--expires=-1h"}, {"create", "api", "--expires=10000h"}, {"create", "api", "--monthly-requests", "-1"}, {"create", "api", "--monthly-bytes=-1"}, {"create", "api", "--rate=-1"}, {"create", "api", "--rate"}, {"create", "api", "--unknown=1"}, {"revoke", "api", "../secret"}} {
		if _, err := parseMeteringOptions("grant", args, now); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if _, err := parseMeteringOptions("usage", []string{"api", "--month=2026-13"}, now); err == nil {
		t.Fatal("accepted invalid month")
	}
	if _, err := parseMeteringOptions("usage", []string{"--help"}, now); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func TestMeteringCLICorrectedUsageAndGrantList(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		args                   []string
		endpoint, since, month string
	}{{nil, "", "", "2026-10"}, {[]string{"--since", "24h"}, "", "24h", ""}, {[]string{"--tunnel=api", "--since=1h"}, "api", "1h", ""}, {[]string{"--since", "2h", "--tunnel", "api"}, "api", "2h", ""}} {
		o, err := parseMeteringOptions("usage", test.args, now)
		if err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		if o.endpoint != test.endpoint || o.since != test.since || o.month != test.month {
			t.Fatalf("options=%+v", o)
		}
	}
	for _, args := range [][]string{{"--tunnel="}, {"--tunnel=../api"}, {"--tunnel=api", "other"}, {"--since="}, {"--since=-1h"}, {"--since=0s"}, {"--since=1ns"}, {"--since=bad"}, {"--since=1h", "--month=2026-10"}, {"api", "extra"}} {
		if _, err := parseMeteringOptions("usage", args, now); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{{"list"}, {"list", "api"}} {
		o, err := parseMeteringOptions("grant", args, now)
		if err != nil || o.action != "list" {
			t.Fatalf("%v: %v %v", args, o, err)
		}
	}
}
