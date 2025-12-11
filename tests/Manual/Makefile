# Makefile for OpenSSL TLS 1.3 Testing
# Usage: make [target]

# Variables
OPENSSL = openssl
PORT = 4433
HOST = localhost
CERT_DIR = certs
CERT_DAYS = 365
RSA_BITS = 2048
EC_CURVE = prime256v1

# Color output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

.PHONY: help clean cert-simple cert-ca cert-rsa cert-ec test-server test-server-rsa test-server-ec test-client run-php show-commands all

help: ## Show this help message
	@echo "$(GREEN)OpenSSL TLS 1.3 Testing Makefile$(NC)"
	@echo "$(YELLOW)Usage:$(NC) make [target]"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

all: cert-rsa cert-ec ## Generate RSA and ECC certificates

init: ## Initialize certificate directory
	@echo "$(YELLOW)Creating certificate directory...$(NC)"
	@mkdir -p $(CERT_DIR)

clean: ## Clean all generated certificates
	@echo "$(RED)Cleaning certificates...$(NC)"
	@rm -rf $(CERT_DIR)

# RSA self-signed certificate
cert-rsa: init ## Generate RSA self-signed certificate (server_rsa.crt/key)
	@echo "$(GREEN)Generating RSA self-signed certificate...$(NC)"
	@$(OPENSSL) req -x509 -newkey rsa:$(RSA_BITS) -keyout $(CERT_DIR)/server_rsa.key \
		-out $(CERT_DIR)/server_rsa.crt -days $(CERT_DAYS) -nodes \
		-subj "/C=US/ST=Test/L=Test/O=Test/CN=$(HOST)"
	@echo "$(GREEN)✓ RSA certificate generated$(NC)"
	@echo "  Key: $(CERT_DIR)/server_rsa.key"
	@echo "  Cert: $(CERT_DIR)/server_rsa.crt"

# ECC self-signed certificate
cert-ec: init ## Generate ECC self-signed certificate (server_ec.crt/key)
	@echo "$(GREEN)Generating ECC self-signed certificate ($(EC_CURVE))...$(NC)"
	@$(OPENSSL) ecparam -genkey -name $(EC_CURVE) -out $(CERT_DIR)/server_ec.key
	@$(OPENSSL) req -new -x509 -key $(CERT_DIR)/server_ec.key \
		-out $(CERT_DIR)/server_ec.crt -days $(CERT_DAYS) \
		-subj "/C=US/ST=Test/L=Test/O=Test/CN=$(HOST)"
	@echo "$(GREEN)✓ ECC certificate generated$(NC)"
	@echo "  Key: $(CERT_DIR)/server_ec.key"
	@echo "  Cert: $(CERT_DIR)/server_ec.crt"

# Legacy aliases
cert-simple: cert-rsa ## Alias for cert-rsa (backwards compatibility)

# CA-based PKI setup (RSA)
cert-ca: init ## Generate CA and RSA server certificates
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
test-server-rsa: ## Start OpenSSL s_server with RSA certificate (TLS 1.3)
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3, RSA) on port $(PORT)...$(NC)"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug

test-server-ec: ## Start OpenSSL s_server with ECC certificate (TLS 1.3)
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3, ECC) on port $(PORT)...$(NC)"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug

test-server: test-server-rsa ## Start OpenSSL s_server (default: RSA)

test-server-verbose: ## Start OpenSSL s_server (TLS 1.3) with verbose output
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 verbose) on port $(PORT)...$(NC)"
	@echo "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug  -tlsextdebug  -security_debug_verbose -msg -state"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -state

test-server-groups: ## Start OpenSSL s_server (TLS 1.3) with specific groups
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with groups) on port $(PORT)...$(NC)"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -groups X25519:P-256:P-384 -debug

test-server-ciphersuites: ## Start OpenSSL s_server (TLS 1.3) with specific cipher suites
	@echo "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with cipher suites) on port $(PORT)...$(NC)"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug

# Test clients (TLS 1.3 only)
test-client: ## Connect with OpenSSL s_client (TLS 1.3)
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3) to $(HOST):$(PORT)...$(NC)"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts

test-client-verbose: ## Connect with OpenSSL s_client (TLS 1.3) with verbose output
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 verbose) to $(HOST):$(PORT)...$(NC)"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg -groups P-256 -keylogfile $(CERT_DIR)/client.keylog

test-client-groups: ## Connect with OpenSSL s_client (TLS 1.3) with specific groups
	@echo "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 with groups) to $(HOST):$(PORT)...$(NC)"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts

# PHP test
run-php: ## Run PHP test client
	@echo "$(GREEN)Running PHP test client...$(NC)"
	@php test/manual/test_client.php

# Utility commands
show-cert-rsa: ## Display RSA server certificate details
	@echo "$(GREEN)RSA Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout

show-cert-ec: ## Display ECC server certificate details
	@echo "$(GREEN)ECC Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout

show-cert: show-cert-rsa ## Display server certificate details (default: RSA)

show-commands: ## Show useful OpenSSL commands for debugging (TLS 1.3)
	@echo "$(GREEN)Useful OpenSSL Commands for TLS 1.3 Debugging:$(NC)"
	@echo ""
	@echo "$(YELLOW)Server commands (RSA):$(NC)"
	@echo "  $$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug"
	@echo ""
	@echo "$(YELLOW)Server commands (ECC):$(NC)"
	@echo "  $$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug"
	@echo ""
	@echo "$(YELLOW)Client commands:$(NC)"
	@echo "  $$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@echo "  $$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg"
	@echo ""
	@echo "$(YELLOW)Certificate inspection:$(NC)"
	@echo "  $$ $(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout"
	@echo "  $$ $(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout"

# Quick test scenarios
quick-test: cert-rsa ## Quick test: generate RSA cert and start server
	@echo "$(GREEN)Quick test setup complete!$(NC)"
	@echo "$(YELLOW)Now run in another terminal:$(NC)"
	@echo "  $$ make test-client"
	@echo ""
	@$(MAKE) test-server-rsa

quick-test-ec: cert-ec ## Quick test: generate ECC cert and start server
	@echo "$(GREEN)Quick ECC test setup complete!$(NC)"
	@echo "$(YELLOW)Now run in another terminal:$(NC)"
	@echo "  $$ make test-client"
	@echo ""
	@$(MAKE) test-server-ec

.DEFAULT_GOAL := help
