package localserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Callback struct {
	EnrollmentID string
	Status       string
}

type Server struct {
	server   *http.Server
	callback chan Callback
	once     sync.Once
}

func Start(callbackURL string) (*Server, error) {
	host, port, err := parseCallbackURL(callbackURL)
	if err != nil {
		return nil, err
	}

	callbacks := make(chan Callback, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><h1>Keyward Client</h1><p>Running.</p></body></html>"))
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		callback := Callback{
			EnrollmentID: r.URL.Query().Get("enrollment_id"),
			Status:       r.URL.Query().Get("status"),
		}
		select {
		case callbacks <- callback:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><h1>Authorization successful</h1><p>You can return to the Keyward client.</p></body></html>"))
	})

	httpServer := &http.Server{Addr: net.JoinHostPort(host, port), Handler: mux}
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return nil, err
	}

	server := &Server{server: httpServer, callback: callbacks}
	go func() {
		_ = httpServer.Serve(listener)
	}()
	return server, nil
}

func (s *Server) Wait(ctx context.Context) (Callback, error) {
	select {
	case callback := <-s.callback:
		return callback, nil
	case <-ctx.Done():
		return Callback{}, ctx.Err()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		err = s.server.Shutdown(ctx)
	})
	return err
}

func (s *Server) ShutdownSoon() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
}

func parseCallbackURL(callbackURL string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	if err != nil {
		return "", "", err
	}
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		return "", "", fmt.Errorf("callback URL must include host and port: %w", err)
	}
	if host != "127.0.0.1" && host != "localhost" {
		return "", "", fmt.Errorf("callback URL must bind to localhost")
	}
	return host, port, nil
}
