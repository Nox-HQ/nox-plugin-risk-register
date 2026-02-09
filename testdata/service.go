package service

import (
	"database/sql"
	"net/http"
	"io/ioutil"
)

// TODO: Fix security vulnerability in auth handler — triggers RISK-001.
func handleAuth() {}

// FIXME: sanitize user input before SQL query — triggers RISK-001.
func handleQuery() {}

// Deprecated API usage — triggers RISK-002.
func readFile() {
	data, _ := ioutil.ReadAll(nil)
	_ = data
}

// Single DB connection without pooling — triggers RISK-003.
func connectDB() {
	db, _ := sql.Open("postgres", "postgres://localhost/mydb")
	_ = db
}

// External call without retry — triggers RISK-004.
func callService() {
	resp, _ := http.Get("https://api.example.com/data")
	_ = resp
}
