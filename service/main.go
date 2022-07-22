package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter().StrictSlash(true)
	/*
		// Only matches if domain is "www.example.com".
		r.Host("www.example.com")
		// Matches a dynamic subdomain.
		r.Host("{subdomain:[a-z]+}.example.com")
	*/
	r.HandleFunc("/", HomeHandler).Methods(http.MethodGet)
	r.HandleFunc("/v1/verify", VerifyHandlerV1).Methods(http.MethodPost)
	// r.HandleFunc("/v2/verify", VerifyHandlerV2).Methods(http.MethodGet)
	// r.HandleFunc("/articles/{category}", ArticlesHandler).Methods(http.MethodGet)
	http.Handle("/", r)

	address := "127.0.0.1:8000"
	fmt.Printf("Starting HTTP server on %v ...\n", address)
	srv := &http.Server{
		Handler: r,
		Addr:    address,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// func ProductsHandler(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprintf(w, "Category: %v\n", vars["category"])
// }

// func ArticlesHandler(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprintf(w, "Articles: %v\n", vars["category"])
// }
