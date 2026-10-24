// Package localhttp provides explicit-loopback addressing and bounded serving.
package localhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

// Private development defaults, not protocol policy.
const (
	headerTimeout   = 5 * time.Second
	readTimeout     = 15 * time.Second
	writeTimeout    = 15 * time.Second
	idleTimeout     = 30 * time.Second
	shutdownTimeout = 5 * time.Second
)

// Address requires an explicit loopback IP and numeric port. localhost is
// normalized without DNS; allowZero permits a port selected during binding.
func Address(value string, allowZero bool) (address string, err error) {
	defer err2.Handle(&err)

	host, port := try.To2(net.SplitHostPort(value))
	if host == "localhost" {
		host = "127.0.0.1" // No DNS lookup, including for localhost.
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("host must be explicit loopback")
	}
	if port == "" || strings.IndexFunc(port, func(c rune) bool {
		return c < '0' || c > '9'
	}) >= 0 {
		return "", errors.New("port must be numeric")
	}
	number := try.To1(strconv.ParseUint(port, 10, 16))
	if number == 0 && !allowZero {
		return "", errors.New("HTTP endpoint port must be nonzero")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(number, 10)), nil
}

// Serve takes ownership of listener, joins the server, and finishes bounded
// shutdown before returning. Callers retain ownership of handler resources.
func Serve(
	ctx context.Context, listener net.Listener, handler http.Handler,
) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	finished := make(chan error, 1)
	// Serve always closes its listener; never close it twice here.
	go func() { finished <- server.Serve(listener) }()

	select {
	case serveErr := <-finished:
		return errors.Join(
			fmt.Errorf("HTTP server exited unexpectedly: %w", serveErr),
			server.Close(),
		)
	case <-ctx.Done():
		// A completed Serve before our shutdown is still an unexpected exit,
		// even when its error happens to be http.ErrServerClosed.
		select {
		case serveErr := <-finished:
			return errors.Join(
				fmt.Errorf("HTTP server exited unexpectedly: %w", serveErr),
				server.Close(),
			)
		default:
		}
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), shutdownTimeout,
	)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	serveErr := <-finished
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil // Only intentional shutdown may consume this sentinel.
	}
	return errors.Join(shutdownErr, serveErr)
}
