package host

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailSender sends emails via SMTP
type EmailSender struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
}

// NewEmailSender creates a new SMTP email sender
// Returns nil if SMTP is not configured (all fields empty)
func NewEmailSender(host, port, user, password, from string) *EmailSender {
	if host == "" {
		return nil
	}
	if port == "" {
		port = "587"
	}
	return &EmailSender{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		From:     from,
	}
}

// Send sends an email via SMTP
func (s *EmailSender) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)
	// Auth (nil if no credentials - some SMTP servers allow unauthenticated)
	var auth smtp.Auth
	if s.User != "" && s.Password != "" {
		auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
	}
	return smtp.SendMail(addr, auth, s.From, []string{to}, s.message(to, subject, body))
}

func (s *EmailSender) message(to, subject, body string) []byte {
	// Build email message
	msg := strings.Builder{}
	_, _ = fmt.Fprintf(&msg, "From: %s\r\n", s.From)
	_, _ = fmt.Fprintf(&msg, "To: %s\r\n", to)
	_, _ = fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return []byte(msg.String())
}

// SendContext uses the same SMTP configuration and message format with a
// bounded connection lifetime, so the alert worker can join server shutdown.
func (s *EmailSender) SendContext(ctx context.Context, to, subject, body string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, s.Port))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if s.User != "" && s.Password != "" {
		if err = c.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err = c.Mail(s.From); err != nil {
		return err
	}
	if err = c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(s.message(to, subject, body)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// SendMagicLink sends a magic link email for passwordless login
func (s *EmailSender) SendMagicLink(to, magicLinkURL string) error {
	subject := "Your tunn.to login link"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">Login to tunn.to</h2>
  <p>Click the button below to log in. This link expires in 5 minutes.</p>
  <p style="margin: 30px 0;">
    <a href="%s" style="background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Log in to tunn.to</a>
  </p>
  <p style="color: #666; font-size: 14px;">Or copy this link: <code style="background: #f5f5f5; padding: 2px 6px;">%s</code></p>
  <p style="color: #999; font-size: 12px; margin-top: 40px;">If you didn't request this email, you can safely ignore it.</p>
</body>
</html>`, magicLinkURL, magicLinkURL)

	return s.Send(to, subject, body)
}
