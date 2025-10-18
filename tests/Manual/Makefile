# Makefile for OpenSSL TLS 1.3 Testing
# Usage: make [target]

# Variables
OPENSSL = openssl
PORT = 4433
HOST = localhost
CERT_DIR = certs
CERT_DAYS = 365
RSA_BITS = 2048

# Color output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

.PHONY: help clean cert-simple cert-ca test-server test-client run-php show-commands all

help: ## Show this help message
	@echo "$(GREEN)OpenSSL TLS 1.3 Testing Makefile$(NC)"
	@echo "$(YELLOW)Usage:$(NC) make [target]"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $1, $2}'

all: cert-simple ## Generate certificates and show commands

init: ## Initialize certificate directory
	@echo "$(YELLOW)Creating certificate directory...$(NC)"
	@mkdir -p $(CERT_DIR)

clean: ## Clean all generated certificates
	@echo "$(RED)Cleaning certificates...$(NC)"
	@rm -rf $(CERT_DIR)

# Simple self-signed certificate
cert-simple: init ## Generate self-signed certificate
	@echo "$(GREEN)Generating self-signed certificate...$(NC)"
	@$(OPENSSL) req -x509 -newkey rsa:$(RSA_BITS) -keyout $(CERT_DIR)/server.key \
		-out $(CERT_DIR)/server.crt -days $(CERT_DAYS) -nodes \
		-subj "/C=US/ST=Test/L=Test/O=Test/CN=$(HOST)"
	@echo "$(GREEN)✓ Self-signed certificate generated$(NC)"
	@echo "  Key: $(CERT_DIR)/server.key"
	@echo "  Cert: $(CERT_DIR)/server.crt"

# CA-based PKI setup
cert-ca: init ## Generate CA and server certificates
	@echo "$(GREEN)Setting up mini PKI...$(NC)"

	@echo "$(YELLOW)1. Generating CA private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/ca.key $(RSA_BITS)

	@echo "$(YELLOW)2. Generating CA certificate...$(NC)"
	@$(OPENSSL) req -new -x509 -days $(CERT_DAYS) -key $(CERT_DIR)/ca.key \
		-out $(CERT_DIR)/ca.crt \
		-subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

	@echo "$(YELLOW)3. Generating server private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/server.key $(RSA_BITS)

	@echo "$(YELLOW)4. Generating server CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/server.key \
		-out $(CERT_DIR)/server.csr \
		-subj "/C=US/ST=Test/L=Test/O=Test Server/CN=$(HOST)"

	@echo "$(YELLOW)5. Signing server certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/server.csr \
		-CA $(CERT_DIR)/ca.crt -CAkey $(CERT_DIR)/ca.key \
		-CAcreateserial -out $(CERT_DIR)/server.crt \
		-days $(CERT_DAYS)

	@echo "$(GREEN)✓ CA-based PKI generated$(NC)"
	@echo "  CA Cert: $(CERT_DIR)/ca.crt"
	@echo "  Server Key: $(CERT_DIR)/server.key"
	@echo "  Server Cert: $(CERT_DIR)/server.crt"

# Test servers (TLS 1.3 only)
test-server: ## Start OpenSSL s_server (TLS 1.3)
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3) on port $(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -debug

test-server-verbose: ## Start OpenSSL s_server (TLS 1.3) with verbose output
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 verbose) on port $(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug  -tlsextdebug  -security_debug_verbose -msg -state"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -state

test-server-groups: ## Start OpenSSL s_server (TLS 1.3) with specific groups
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with groups) on port $(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -groups X25519:P-256:P-384 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -groups X25519:P-256:P-384 -debug

test-server-ciphersuites: ## Start OpenSSL s_server (TLS 1.3) with specific cipher suites
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with cipher suites) on port $(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug

# Test clients (TLS 1.3 only)
test-client: ## Connect with OpenSSL s_client (TLS 1.3)
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3) to $(HOST):$(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts

test-client-verbose: ## Connect with OpenSSL s_client (TLS 1.3) with verbose output
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 verbose) to $(HOST):$(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg

test-client-groups: ## Connect with OpenSSL s_client (TLS 1.3) with specific groups
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 with groups) to $(HOST):$(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts

# PHP test
run-php: ## Run PHP test client
	@echo "$(GREEN)Running PHP test client...$(NC)"
	@php test/manual/test_client.php

# Utility commands
show-cert: ## Display server certificate details
	@echo "$(GREEN)Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server.crt -text -noout

show-commands: ## Show useful OpenSSL commands for debugging (TLS 1.3)
	@echo "$(GREEN)Useful OpenSSL Commands for TLS 1.3 Debugging:$(NC)"
	@echo ""
	@echo "$(YELLOW)Server commands:$(NC)"
	@echo "  $ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -debug"
	@echo "  $ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -debug -msg -state"
	@echo "  $ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -groups X25519:P-256:P-384 -debug"
	@echo ""
	@echo "$(YELLOW)Client commands:$(NC)"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts"
	@echo ""
	@echo "$(YELLOW)Certificate inspection:$(NC)"
	@echo "  $ $(OPENSSL) x509 -in $(CERT_DIR)/server.crt -text -noout"
	@echo "  $ $(OPENSSL) rsa -in $(CERT_DIR)/server.key -text -noout"
	@echo ""
	@echo "$(YELLOW)Testing TLS 1.3 specific features:$(NC)"
	@echo "  $ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384"
	@echo ""
	@echo "$(YELLOW)TLS 1.3 session resumption:$(NC)"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_out session.pem"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_in session.pem"
	@echo ""
	@echo "$(YELLOW)TLS 1.3 0-RTT (early data):$(NC)"
	@echo "  $ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -tls1_3 -early_data"
	@echo "  $ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_in session.pem -early_data"

# Quick test scenarios
quick-test: cert-simple ## Quick test: generate cert and start server
	@echo "$(GREEN)Quick test setup complete!$(NC)"
	@echo "$(YELLOW)Now run in another terminal:$(NC)"
	@echo "  $$ make test-client"
	@echo "  $$ make run-php"
	@echo ""
	@$(MAKE) test-server

parallel-test: ## Run server and provide client commands (requires tmux)
	@command -v tmux >/dev/null 2>&1 || { echo "$(RED)tmux is required but not installed.$(NC)" >&2; exit 1; }
	@echo "$(GREEN)Starting parallel test session...$(NC)"
	@tmux new-session -d -s tls-test "make test-server"
	@tmux split-window -h -t tls-test
	@tmux send-keys -t tls-test:0.1 "sleep 2 && make test-client" Enter
	@tmux attach-session -t tls-test

.DEFAULT_GOAL := help
