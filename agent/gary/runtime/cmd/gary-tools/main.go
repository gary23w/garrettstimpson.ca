package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/service"
)

func main() {
	catalog := flag.Bool("catalog", false, "write Gary tool schemas as JSON without starting services")
	skillDir := flag.String("skills", "../skills", "security skill directory")
	addr := flag.String("addr", "127.0.0.1:8790", "Gary gateway listen address")
	adminAddr := flag.String("admin", "127.0.0.1:8787", "upstream administration API listen address (empty disables)")
	data := flag.String("data", "./data", "persistent runtime data")
	proxy := flag.String("proxy", "127.0.0.1:8788", "HTTP recording proxy")
	flag.Parse()
	if *catalog {
		tools, err := server.GaryBuiltinCatalog(*skillDir)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"sourceCommit": server.GarySourceCommit, "tools": tools}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if value := os.Getenv("GARY_PG_DSN"); value != "" {
		_ = os.Setenv("GARY_PG_DSN", value)
	}
	token := os.Getenv("GARY_RUNTIME_TOKEN")
	if len(token) < 24 {
		log.Fatal("GARY_RUNTIME_TOKEN must contain at least 24 characters")
	}
	_ = os.Unsetenv("GARY_RUNTIME_TOKEN")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mgr, err := server.NewManager(*data, *proxy)
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Close()
	if err = mgr.SetTrafficEnabled(true); err != nil {
		log.Fatal(err)
	}
	keyDir := filepath.Join(*data, "gary-keys")
	if err = os.MkdirAll(keyDir, 0700); err != nil {
		log.Fatal(err)
	}
	s := server.New(ctx, mgr, *skillDir, *data, keyDir)
	g, err := server.NewGaryGateway(s, token, os.Getenv("GARY_TASK_ID"))
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	servers := []*http.Server{{Addr: *addr, Handler: g, ReadHeaderTimeout: 10 * time.Second}}
	if *adminAddr != "" {
		servers = append(servers, &http.Server{Addr: *adminAddr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second})
	}
	for _, srv := range servers {
		go func(h *http.Server) {
			if err := h.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Print(err)
				stop()
			}
		}(srv)
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
}
