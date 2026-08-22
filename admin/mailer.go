package admin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
)

// ErrMailerNotConfigured 表示 SMTP 未配置/未启用（调用方据此回落 dev URL 行为）。
var ErrMailerNotConfigured = errors.New("mailer: SMTP not configured")

// smtpMailer 读取 system_settings 的 smtp 配置段发信；未配置时返回 ErrMailerNotConfigured。
type smtpMailer struct {
	db *database.DB
}

func (m *smtpMailer) SendVerificationEmail(ctx context.Context, to, verifyURL string) error {
	return m.send(ctx, to, "验证您的邮箱", verificationEmailBody(verifyURL))
}

func (m *smtpMailer) SendPasswordResetEmail(ctx context.Context, to, resetURL string) error {
	return m.send(ctx, to, "重置您的密码", resetPasswordEmailBody(resetURL))
}

func (m *smtpMailer) send(ctx context.Context, to, subject, body string) error {
	cfg, err := m.db.LoadSMTPConfig(ctx)
	if err != nil {
		return fmt.Errorf("读取 SMTP 配置失败: %w", err)
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.Host) == "" {
		return ErrMailerNotConfigured
	}
	from := strings.TrimSpace(cfg.From)
	if from == "" {
		from = strings.TrimSpace(cfg.Username)
	}
	if from == "" {
		return ErrMailerNotConfigured
	}
	if err := sendSMTPMail(ctx, cfg, from, to, subject, body); err != nil {
		return fmt.Errorf("SMTP 发送失败: %w", err)
	}
	log.Printf("[user-mailer] 已发送邮件: to=%s subject=%s", security.SanitizeLog(to), subject)
	return nil
}

// sendSMTPMail 通过 net/smtp 发送单封邮件；支持 ssl（隐式 TLS）、starttls、none 三种安全模式。
func sendSMTPMail(ctx context.Context, cfg *database.SMTPConfig, from, to, subject, body string) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var conn net.Conn
	var err error
	if cfg.Security == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	if cfg.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{
				ServerName:         cfg.Host,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			}); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(cfg.Username) != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	header := "From: " + formatMailHeader(cfg.FromName, from) + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n"
	if _, err := io.WriteString(w, header+body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func formatMailHeader(name, addr string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return addr
	}
	return mime.QEncoding.Encode("UTF-8", name) + " <" + addr + ">"
}

func verificationEmailBody(verifyURL string) string {
	return "欢迎注册！请点击以下链接完成邮箱验证（24 小时内有效）：\r\n\r\n" +
		verifyURL + "\r\n\r\n如果这不是您本人的操作，请忽略本邮件。"
}

func resetPasswordEmailBody(resetURL string) string {
	return "您正在重置密码。请点击以下链接设置新密码（24 小时内有效）：\r\n\r\n" +
		resetURL + "\r\n\r\n如果这不是您本人的操作，请忽略本邮件。"
}
