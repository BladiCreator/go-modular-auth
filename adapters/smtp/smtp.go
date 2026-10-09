// Package smtp provides an SMTP implementation of GoModularAuth email.Sender.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/BladiCreator/go-modular-auth/email"
)

// Config configures the SMTP email sender.
type Config struct {
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	InsecureSkipVerify bool
	UseTLS             bool
}

// Sender delivers emails via SMTP.
type Sender struct {
	cfg Config
}

var _ email.Sender = (*Sender)(nil)

// New creates a new SMTP email sender.
func New(cfg Config) (*Sender, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp: host is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	if cfg.From == "" {
		cfg.From = cfg.Username
	}
	if cfg.From == "" {
		return nil, errors.New("smtp: from address is required")
	}
	return &Sender{cfg: cfg}, nil
}

// Send sends an email message via SMTP.
func (s *Sender) Send(ctx context.Context, msg email.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(msg.To) == "" {
		return errors.New("smtp: recipient 'To' is required")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	// Format MIME email body
	boundary := "=_gomodularauth_boundary"
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", s.cfg.From))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", msg.To))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
	sb.WriteString("MIME-Version: 1.0\r\n")

	if msg.HTML != "" && msg.Text != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))
		sb.WriteString(fmt.Sprintf("--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", boundary, msg.Text))
		sb.WriteString(fmt.Sprintf("--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n", boundary, msg.HTML))
		sb.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else if msg.HTML != "" {
		sb.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		sb.WriteString(msg.HTML)
	} else {
		sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		sb.WriteString(msg.Text)
	}

	rawBody := []byte(sb.String())

	// Build auth
	var auth smtp.Auth
	if s.cfg.Username != "" && s.cfg.Password != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}

	// Dial with context
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial failed: %w", err)
	}
	defer conn.Close()

	if s.cfg.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         s.cfg.Host,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp: tls handshake failed: %w", err)
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp: client creation failed: %w", err)
	}
	defer client.Close()

	// STARTTLS if not already on implicit TLS
	if !s.cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName:         s.cfg.Host,
				InsecureSkipVerify: s.cfg.InsecureSkipVerify,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("smtp: starttls failed: %w", err)
			}
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth failed: %w", err)
		}
	}

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp: mail from failed: %w", err)
	}

	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp: rcpt to failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: data command failed: %w", err)
	}

	if _, err := w.Write(rawBody); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp: write body failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close data failed: %w", err)
	}

	return client.Quit()
}
