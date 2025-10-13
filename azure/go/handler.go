package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

// Request represents the incoming HTTP request body
type Request struct {
	Filename string `json:"filename"`
	Password string `json:"password"`
	Action   string `json:"action"`
}

// Response represents the HTTP response body
type Response struct {
	Message  string `json:"message"`
	Content  string `json:"content,omitempty"`
	Error    string `json:"error,omitempty"`
	FileInfo string `json:"file_info,omitempty"`
}

// SECURITY VULNERABILITY: Path Traversal
// This function reads files based on user input without proper validation,
// allowing attackers to access arbitrary files on the system.
//
// VULNERABILITIES:
// 1. Path traversal - Reading files without path validation (HIGH)
// 2. Uses golang.org/x/crypto with potential vulnerabilities

// FileHandler is the main Azure Function handler
func FileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		sendResponse(w, http.StatusMethodNotAllowed, Response{
			Error: "Method not allowed",
		})
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, Response{
			Error: "Invalid JSON body",
		})
		return
	}

	// VULNERABILITY: Path Traversal
	// User-provided filename is used directly without validation
	// An attacker can use paths like: "../../etc/passwd" or "../../../config/secrets.yml"
	if req.Filename != "" && req.Action == "read" {
		baseDir := "/tmp/files"

		// DANGEROUS: filepath.Join doesn't prevent traversal attacks
		// This is vulnerable to path traversal
		filePath := filepath.Join(baseDir, req.Filename)

		fmt.Printf("Attempting to read file: %s\n", filePath)

		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			sendResponse(w, http.StatusInternalServerError, Response{
				Error:   "Failed to read file",
				Message: err.Error(),
			})
			return
		}

		sendResponse(w, http.StatusOK, Response{
			Message:  "File read successfully",
			Content:  string(content),
			FileInfo: filePath,
		})
		return
	}

	// Hash password using bcrypt (demonstrates vulnerable golang.org/x/crypto usage)
	if req.Password != "" && req.Action == "hash" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			sendResponse(w, http.StatusInternalServerError, Response{
				Error: "Failed to hash password",
			})
			return
		}

		sendResponse(w, http.StatusOK, Response{
			Message: "Password hashed successfully",
			Content: string(hashedPassword),
		})
		return
	}

	sendResponse(w, http.StatusOK, Response{
		Message: "File service ready",
	})
}

func sendResponse(w http.ResponseWriter, statusCode int, response Response) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func main() {
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddr = ":" + val
	}

	http.HandleFunc("/api/FileHandler", FileHandler)
	fmt.Printf("Starting server on %s\n", listenAddr)
	http.ListenAndServe(listenAddr, nil)
}
