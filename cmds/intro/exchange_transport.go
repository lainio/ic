package intro

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/nats-io/nats.go"
)

// Private disposable-demo limits/markers, not a public wire-format version.
const (
	exchangePayloadLimit = 64 * 1024
	exchangeErrorHeader  = "Intro-Demo-Error"
	exchangeVerified     = "acceptance-verified"
)

func (cfg exchangeConfig) validate() (endpoint string, err error) {
	defer err2.Handle(&err)

	if len(cfg.session) == 0 || len(cfg.session) > 64 {
		return "", errors.New("--session must contain 1..64 ASCII token bytes")
	}
	for _, c := range cfg.session {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return "", errors.New("--session allows only letters, digits, _ and -")
	}
	if cfg.timeout <= 0 {
		return "", errors.New("--timeout must be positive")
	}
	return exchangeEndpoint(cfg.natsURL)
}

func exchangeEndpoint(value string) (endpoint string, err error) {
	defer err2.Handle(&err)

	u := try.To1(url.Parse(value))
	if u.Scheme != "nats" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.Contains(value, ",") {
		return "", errors.New("--nats-url requires one plain loopback NATS URL")
	}
	host := u.Hostname()
	if host == "localhost" {
		host = "127.0.0.1" // Avoid DNS changing the loopback-only boundary.
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("--nats-url host must be loopback")
	}
	port := u.Port()
	if port == "" {
		port = "4222"
	}
	number := try.To1(strconv.Atoi(port))
	if number < 1 || number > 65535 {
		return "", errors.New("--nats-url port must be 1..65535")
	}
	return "nats://" + net.JoinHostPort(ip.String(), port), nil
}

func exchangeSubjects(session string) (offer, acceptance string) {
	prefix := "ic.intro-demo." + session
	return prefix + ".offer", prefix + ".acceptance"
}

func connectExchange(ctx context.Context, endpoint string) (*nats.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("exchange requires a deadline")
	}
	remaining := time.Until(deadline)
	return nats.Connect(endpoint, nats.NoReconnect(),
		nats.Timeout(remaining), nats.FlusherTimeout(remaining))
}

func checkExchangePayload(data []byte) error {
	if len(data) > exchangePayloadLimit {
		return errors.New("demo payload exceeds 64 KiB")
	}
	return nil
}

func checkExchangeMessage(msg *nats.Msg) error {
	if diagnostic, rejected := msg.Header[exchangeErrorHeader]; rejected {
		return fmt.Errorf(
			"peer rejected exchange: %.65536s",
			strings.Join(diagnostic, " "),
		)
	}
	return checkExchangePayload(msg.Data)
}

func checkExchangeRequest(msg *nats.Msg) error {
	if msg.Reply == "" {
		return nats.ErrMsgNoReply
	}
	return checkExchangeMessage(msg)
}

func requestExchange(
	ctx context.Context, nc *nats.Conn, subject string, data []byte,
) (payload []byte, err error) {
	defer err2.Handle(&err)

	try.To(checkExchangePayload(data))
	msg := try.To1(nc.RequestWithContext(ctx, subject, data))
	try.To(checkExchangeMessage(msg))
	return msg.Data, nil
}

func replyExchange(
	ctx context.Context, nc *nats.Conn, request *nats.Msg,
	data []byte, cause error,
) error {
	if request.Reply == "" {
		return errors.Join(cause, nats.ErrMsgNoReply)
	}
	if cause == nil {
		cause = checkExchangePayload(data)
	}
	reply := &nats.Msg{Data: data}
	if cause != nil {
		// Diagnostics only: no error identity or errors.Is across the wire.
		diagnostic := strings.NewReplacer("\r", " ", "\n", " ").
			Replace(cause.Error())
		if len(diagnostic) > exchangePayloadLimit {
			diagnostic = diagnostic[:exchangePayloadLimit]
		}
		reply = &nats.Msg{
			Header: nats.Header{exchangeErrorHeader: {diagnostic}},
		}
	}
	if err := request.RespondMsg(reply); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, nc.FlushWithContext(ctx))
}
