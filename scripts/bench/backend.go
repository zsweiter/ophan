// Minimal upstream for the gateway benchmark: answers "pong" on every path.
//
//	go run backend.go 127.0.0.1:18081
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := "127.0.0.1:18081"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	body := []byte("pong")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
	})

	log.Fatal(http.ListenAndServe(addr, nil))
}
