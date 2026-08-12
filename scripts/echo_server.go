package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type EchoResponse struct {
	Message string              `json:"message"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type UserResponse struct {
	Message string `json:"message"`
}

// go run main.go -socket /tmp/api.sock
func main() {
	socketPath := flag.String("socket", "", "Unix Domain Socket (ej: /tmp/server.sock)")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		fmt.Printf("request: %s\n", time.Now().String())

		w.Header().Set("Content-Type", "application/json")

		if path == "/echo" {
			resp := EchoResponse{
				Message: "echo",
				Method:  r.Method,
				Path:    path,
				Headers: r.Header,
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.HasPrefix(path, "/users/") {
			username := path[7:]
			if username != "" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(UserResponse{
					Message: fmt.Sprintf("Hello %s", username),
				})
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	})

	server := &http.Server{
		Addr:         ":3000",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  65 * time.Second,
	}

	if *socketPath != "" {
		if err := os.RemoveAll(*socketPath); err != nil {
			fmt.Printf("Error limpiando socket previo: %v\n", err)
			return
		}

		listener, err := net.Listen("unix", *socketPath)
		if err != nil {
			fmt.Printf("Error bindeando a Unix Socket: %v\n", err)
			return
		}

		if err := os.Chmod(*socketPath, 0666); err != nil {
			fmt.Printf("Error configurando permisos del socket: %v\n", err)
			return
		}

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			os.Remove(*socketPath)
			os.Exit(0)
		}()

		fmt.Printf("Server running on Unix Socket: %s\n", *socketPath)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Error ejecutando servidor: %v\n", err)
		}
	} else {
		fmt.Println("Server running on http://localhost:3000")
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Error starting server: %v\n", err)
		}
	}

}
