package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

type bugReportPayload struct {
	Text    string `json:"text"`
	Version string `json:"version"`
	OS      string `json:"os"`
}

func executeReport(args []string, out io.Writer, client *http.Client, endpoint string) error {
	var dry bool
	var text string
	for _, arg := range args {
		if arg == "--dry-run" {
			dry = true
			continue
		}
		if text != "" || strings.HasPrefix(arg, "--") {
			return errors.New("usage: tunn report [--dry-run] \"text\"")
		}
		text = arg
	}
	if strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > 4000 {
		return errors.New("report text must contain 1 to 4000 characters")
	}
	body, err := json.Marshal(bugReportPayload{Text: text, Version: version, OS: runtime.GOOS})
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(out, string(body)); err != nil {
		return err
	}
	if dry {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report failed: %s", resp.Status)
	}
	_, err = io.Copy(out, io.LimitReader(resp.Body, 4096))
	return err
}

func runReport(args []string) {
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := executeReport(args, os.Stdout, client, "https://tunn.to/report"); err != nil {
		fmt.Fprintln(os.Stderr, "tunn report:", err)
		os.Exit(1)
	}
}
