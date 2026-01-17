package host

import (
	"fmt"
	"net/smtp"
	"strings"
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

	// Build email message
	msg := strings.Builder{}
	msg.WriteString(fmt.Sprintf("From: %s\r\n", s.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Auth (nil if no credentials - some SMTP servers allow unauthenticated)
	var auth smtp.Auth
	if s.User != "" && s.Password != "" {
		auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
	}

	return smtp.SendMail(addr, auth, s.From, []string{to}, []byte(msg.String()))
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
