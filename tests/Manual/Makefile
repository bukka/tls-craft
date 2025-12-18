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

SHELL := /bin/bash
.SHELLFLAGS := -ec
ECHO := echo -e

.PHONY: help clean cert-simple cert-ca cert-rsa cert-ec cert-mtls test-server test-server-rsa test-server-ec test-client run-php show-commands all

help: ## Show this help message
	@$(ECHO) "$(GREEN)OpenSSL TLS 1.3 Testing Makefile$(NC)"
	@$(ECHO) "$(YELLOW)Usage:$(NC) make [target]"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

all: cert-rsa cert-ec ## Generate RSA and ECC certificates

init: ## Initialize certificate directory
	@$(ECHO) "$(YELLOW)Creating certificate directory...$(NC)"
	@mkdir -p $(CERT_DIR)

clean: ## Clean all generated certificates
	@$(ECHO) "$(RED)Cleaning certificates...$(NC)"
	@rm -rf $(CERT_DIR)

# RSA self-signed certificate
cert-rsa: init ## Generate RSA self-signed certificate (server_rsa.crt/key)
	@$(ECHO) "$(GREEN)Generating RSA self-signed certificate...$(NC)"
	@$(OPENSSL) req -x509 -newkey rsa:$(RSA_BITS) -keyout $(CERT_DIR)/server_rsa.key \
		-out $(CERT_DIR)/server_rsa.crt -days $(CERT_DAYS) -nodes \
		-subj "/C=US/ST=Test/L=Test/O=Test/CN=$(HOST)"
	@$(ECHO) "$(GREEN)✓ RSA certificate generated$(NC)"
	@$(ECHO) "  Key: $(CERT_DIR)/server_rsa.key"
	@$(ECHO) "  Cert: $(CERT_DIR)/server_rsa.crt"

# ECC self-signed certificate
cert-ec: init ## Generate ECC self-signed certificate (server_ec.crt/key)
	@$(ECHO) "$(GREEN)Generating ECC self-signed certificate ($(EC_CURVE))...$(NC)"
	@$(OPENSSL) ecparam -genkey -name $(EC_CURVE) -out $(CERT_DIR)/server_ec.key
	@$(OPENSSL) req -new -x509 -key $(CERT_DIR)/server_ec.key \
		-out $(CERT_DIR)/server_ec.crt -days $(CERT_DAYS) \
		-subj "/C=US/ST=Test/L=Test/O=Test/CN=$(HOST)"
	@$(ECHO) "$(GREEN)✓ ECC certificate generated$(NC)"
	@$(ECHO) "  Key: $(CERT_DIR)/server_ec.key"
	@$(ECHO) "  Cert: $(CERT_DIR)/server_ec.crt"

# Legacy aliases
cert-simple: cert-rsa ## Alias for cert-rsa (backwards compatibility)

# CA-based PKI setup (RSA)
cert-ca: init ## Generate CA and RSA server certificates
	@$(ECHO) "$(GREEN)Setting up mini PKI...$(NC)"
	@$(ECHO) "$(YELLOW)1. Generating CA private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/ca.key $(RSA_BITS) 2>/dev/null
	@$(ECHO) "$(YELLOW)2. Generating CA certificate...$(NC)"
	@$(OPENSSL) req -new -x509 -days $(CERT_DAYS) -key $(CERT_DIR)/ca.key \
		-out $(CERT_DIR)/ca.crt \
		-subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"
	@$(ECHO) "$(YELLOW)3. Generating server private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/server.key $(RSA_BITS) 2>/dev/null
	@$(ECHO) "$(YELLOW)4. Generating server CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/server.key \
		-out $(CERT_DIR)/server.csr \
		-subj "/C=US/ST=Test/L=Test/O=Test Server/CN=$(HOST)"
	@$(ECHO) "$(YELLOW)5. Signing server certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/server.csr \
		-CA $(CERT_DIR)/ca.crt -CAkey $(CERT_DIR)/ca.key \
		-CAcreateserial -out $(CERT_DIR)/server.crt \
		-days $(CERT_DAYS) 2>/dev/null
	@$(ECHO) "$(GREEN)✓ CA-based PKI generated$(NC)"
	@$(ECHO) "  CA Cert: $(CERT_DIR)/ca.crt"
	@$(ECHO) "  Server Key: $(CERT_DIR)/server.key"
	@$(ECHO) "  Server Cert: $(CERT_DIR)/server.crt"

# Mutual TLS setup (RSA)
cert-mtls: init ## Generate CA, server, and client certificates for mutual TLS
	@$(ECHO) "$(GREEN)Setting up mutual TLS certificates...$(NC)"
	@$(ECHO) "$(YELLOW)1. Generating CA private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/ca.key $(RSA_BITS) 2>/dev/null
	@$(ECHO) "$(YELLOW)2. Generating CA certificate...$(NC)"
	@$(OPENSSL) req -new -x509 -days $(CERT_DAYS) -key $(CERT_DIR)/ca.key \
		-out $(CERT_DIR)/ca.crt \
		-subj "/C=US/ST=Test State/L=Test City/O=Test CA/CN=Test CA Certificate"
	@$(ECHO) "$(YELLOW)3. Generating server private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/server.key $(RSA_BITS) 2>/dev/null
	@$(ECHO) "$(YELLOW)4. Generating server CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/server.key \
		-out $(CERT_DIR)/server.csr \
		-subj "/C=US/ST=Test State/L=Test City/O=Test Server/CN=$(HOST)"
	@$(ECHO) "$(YELLOW)5. Signing server certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/server.csr \
		-CA $(CERT_DIR)/ca.crt -CAkey $(CERT_DIR)/ca.key \
		-CAcreateserial -out $(CERT_DIR)/server.crt \
		-days $(CERT_DAYS) -extfile <(echo "subjectAltName=DNS:$(HOST),DNS:$(HOST),IP:127.0.0.1,IP:::1") 2>/dev/null
	@$(ECHO) "$(YELLOW)6. Generating client private key...$(NC)"
	@$(OPENSSL) genrsa -out $(CERT_DIR)/client.key $(RSA_BITS) 2>/dev/null
	@$(ECHO) "$(YELLOW)7. Generating client CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/client.key \
		-out $(CERT_DIR)/client.csr \
		-subj "/C=US/ST=Test State/L=Test City/O=Test Client/CN=Test Client"
	@$(ECHO) "$(YELLOW)8. Signing client certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/client.csr \
		-CA $(CERT_DIR)/ca.crt -CAkey $(CERT_DIR)/ca.key \
		-CAcreateserial -out $(CERT_DIR)/client.crt \
		-days $(CERT_DAYS) 2>/dev/null
	@$(ECHO) "$(GREEN)✓ Mutual TLS certificates generated$(NC)"
	@$(ECHO) "  CA Cert: $(CERT_DIR)/ca.crt"
	@$(ECHO) "  Server Key: $(CERT_DIR)/server.key"
	@$(ECHO) "  Server Cert: $(CERT_DIR)/server.crt"
	@$(ECHO) "  Client Key: $(CERT_DIR)/client.key"
	@$(ECHO) "  Client Cert: $(CERT_DIR)/client.crt"

# Mutual TLS setup (ECC)
cert-mtls-ec: init ## Generate CA, server, and client ECC certificates for mutual TLS
	@$(ECHO) "$(GREEN)Setting up mutual TLS certificates (ECC)...$(NC)"
	@$(ECHO) "$(YELLOW)1. Generating CA private key (ECC)...$(NC)"
	@$(OPENSSL) ecparam -genkey -name $(EC_CURVE) -out $(CERT_DIR)/ca_ec.key
	@$(ECHO) "$(YELLOW)2. Generating CA certificate...$(NC)"
	@$(OPENSSL) req -new -x509 -days $(CERT_DAYS) -key $(CERT_DIR)/ca_ec.key \
		-out $(CERT_DIR)/ca_ec.crt \
		-subj "/C=US/ST=Test State/L=Test City/O=Test CA/CN=Test CA Certificate"
	@$(ECHO) "$(YELLOW)3. Generating server private key (ECC)...$(NC)"
	@$(OPENSSL) ecparam -genkey -name $(EC_CURVE) -out $(CERT_DIR)/server_ec_mtls.key
	@$(ECHO) "$(YELLOW)4. Generating server CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/server_ec_mtls.key \
		-out $(CERT_DIR)/server_ec_mtls.csr \
		-subj "/C=US/ST=Test State/L=Test City/O=Test Server/CN=$(HOST)"
	@$(ECHO) "$(YELLOW)5. Signing server certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/server_ec_mtls.csr \
		-CA $(CERT_DIR)/ca_ec.crt -CAkey $(CERT_DIR)/ca_ec.key \
		-CAcreateserial -out $(CERT_DIR)/server_ec_mtls.crt \
		-days $(CERT_DAYS) -extfile <(echo "subjectAltName=DNS:$(HOST),DNS:$(HOST),IP:127.0.0.1,IP:::1") 2>/dev/null
	@$(ECHO) "$(YELLOW)6. Generating client private key (ECC)...$(NC)"
	@$(OPENSSL) ecparam -genkey -name $(EC_CURVE) -out $(CERT_DIR)/client_ec.key
	@$(ECHO) "$(YELLOW)7. Generating client CSR...$(NC)"
	@$(OPENSSL) req -new -key $(CERT_DIR)/client_ec.key \
		-out $(CERT_DIR)/client_ec.csr \
		-subj "/C=US/ST=Test State/L=Test City/O=Test Client/CN=Test Client"
	@$(ECHO) "$(YELLOW)8. Signing client certificate with CA...$(NC)"
	@$(OPENSSL) x509 -req -in $(CERT_DIR)/client_ec.csr \
		-CA $(CERT_DIR)/ca_ec.crt -CAkey $(CERT_DIR)/ca_ec.key \
		-CAcreateserial -out $(CERT_DIR)/client_ec.crt \
		-days $(CERT_DAYS) 2>/dev/null
	@$(ECHO) "$(GREEN)✓ Mutual TLS certificates (ECC) generated$(NC)"
	@$(ECHO) "  CA Cert: $(CERT_DIR)/ca_ec.crt"
	@$(ECHO) "  Server Key: $(CERT_DIR)/server_ec_mtls.key"
	@$(ECHO) "  Server Cert: $(CERT_DIR)/server_ec_mtls.crt"
	@$(ECHO) "  Client Key: $(CERT_DIR)/client_ec.key"
	@$(ECHO) "  Client Cert: $(CERT_DIR)/client_ec.crt"

# Test servers (TLS 1.3 only)
test-server-rsa: ## Start OpenSSL s_server with RSA certificate (TLS 1.3)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, RSA) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug

test-server-ec: ## Start OpenSSL s_server with ECC certificate (TLS 1.3)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug

test-server: test-server-rsa ## Start OpenSSL s_server (default: RSA)

test-server-mtls: ## Start OpenSSL s_server with mutual TLS (requires client cert)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Mutual TLS) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server will request client certificate$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -CAfile $(CERT_DIR)/ca.crt -Verify 5 -tls1_3 -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key \
		-CAfile $(CERT_DIR)/ca.crt \
		-Verify 5 \
		-tls1_3 -debug -state -msg

test-server-mtls-ec: ## Start OpenSSL s_server with mutual TLS using ECC certificates
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Mutual TLS, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server will request client certificate$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec_mtls.crt -key $(CERT_DIR)/server_ec_mtls.key -CAfile $(CERT_DIR)/ca_ec.crt -Verify 5 -tls1_3 -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec_mtls.crt -key $(CERT_DIR)/server_ec_mtls.key \
		-CAfile $(CERT_DIR)/ca_ec.crt \
		-Verify 5 \
		-tls1_3 -debug -state -msg

test-server-verbose: ## Start OpenSSL s_server (TLS 1.3) with verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -state"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -state

test-server-groups: ## Start OpenSSL s_server (TLS 1.3) with specific groups
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with groups) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -groups X25519:P-256:P-384 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -groups X25519:P-256:P-384 -debug

test-server-ciphersuites: ## Start OpenSSL s_server (TLS 1.3) with specific cipher suites
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with cipher suites) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug

# Test clients (TLS 1.3 only)
test-client: ## Connect with OpenSSL s_client (TLS 1.3)
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts

test-client-mtls: ## Connect with OpenSSL s_client using client certificate (mutual TLS)
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, Mutual TLS) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Providing client certificate$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -cert $(CERT_DIR)/client.crt -key $(CERT_DIR)/client.key -CAfile $(CERT_DIR)/ca.crt -tls1_3 -debug -state -msg"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) \
		-cert $(CERT_DIR)/client.crt -key $(CERT_DIR)/client.key \
		-CAfile $(CERT_DIR)/ca.crt \
		-tls1_3 -debug -state -msg

test-client-mtls-ec: ## Connect with OpenSSL s_client using ECC client certificate
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, Mutual TLS, ECC) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Providing ECC client certificate$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -cert $(CERT_DIR)/client_ec.crt -key $(CERT_DIR)/client_ec.key -CAfile $(CERT_DIR)/ca_ec.crt -tls1_3 -debug -state -msg"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) \
		-cert $(CERT_DIR)/client_ec.crt -key $(CERT_DIR)/client_ec.key \
		-CAfile $(CERT_DIR)/ca_ec.crt \
		-tls1_3 -debug -state -msg

test-client-verbose: ## Connect with OpenSSL s_client (TLS 1.3) with verbose output
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 verbose) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg -groups P-256 -keylogfile $(CERT_DIR)/client.keylog"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg -groups P-256 -keylogfile $(CERT_DIR)/client.keylog

test-client-groups: ## Connect with OpenSSL s_client (TLS 1.3) with specific groups
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 with groups) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts

# PSK / Session Resumption Testing

test-server-psk: ## Start OpenSSL s_server with PSK support (TLS 1.3)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, PSK enabled) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports session resumption$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 -debug -state -msg

test-server-psk-verbose: ## Start OpenSSL s_server with PSK and verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, PSK verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -keylogfile $(CERT_DIR)/server.keylog -debug -tlsextdebug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 \
		-keylogfile $(CERT_DIR)/server.keylog \
		-debug -tlsextdebug -state -msg

test-client-psk: ## Connect with OpenSSL s_client and save session for resumption
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, save session)...$(NC)"
	@$(ECHO) "$(YELLOW)Session will be saved to $(CERT_DIR)/session.pem$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_out $(CERT_DIR)/session.pem -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_out $(CERT_DIR)/session.pem -showcerts

test-client-psk-resume: ## Connect with OpenSSL s_client and resume session
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, resume session)...$(NC)"
	@$(ECHO) "$(YELLOW)Resuming session from $(CERT_DIR)/session.pem$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_in $(CERT_DIR)/session.pem -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_in $(CERT_DIR)/session.pem -showcerts

test-client-psk-verbose: ## Connect with verbose PSK/resumption logging
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, PSK verbose)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_out $(CERT_DIR)/session.pem -keylogfile $(CERT_DIR)/client.keylog -debug -state -msg"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) \
		-tls1_3 -sess_out $(CERT_DIR)/session.pem \
		-keylogfile $(CERT_DIR)/client.keylog \
		-debug -state -msg

test-php-server: ## Run PHP TLS server
	@$(ECHO) "$(GREEN)Starting PHP TLS server on port $(PORT)...$(NC)"
	@php test/manual/test_server.php

test-php-client: ## Run PHP TLS client
	@$(ECHO) "$(GREEN)Running PHP TLS client connecting to $(HOST):$(PORT)...$(NC)"
	@php test/manual/test_client.php

test-php-client-native: ## Run native PHP TLS client (stream_socket_client)
	@$(ECHO) "$(GREEN)Running native PHP TLS client connecting to $(HOST):$(PORT)...$(NC)"
	@php test/manual/test_client_native.php

# Quick PSK testing scenarios
quick-test-psk: cert-rsa ## Quick PSK test: generate cert, start server with PSK support
	@$(ECHO) "$(GREEN)Quick PSK test setup complete!$(NC)"
	@$(ECHO) "$(YELLOW)Server will issue session tickets for resumption$(NC)"
	@$(ECHO) "$(YELLOW)Now run in another terminal:$(NC)"
	@$(ECHO) "  1. First connection:  \$$ make test-client-psk"
	@$(ECHO) "  2. Resume session:    \$$ make test-client-psk-resume"
	@$(ECHO) "  3. Or use PHP client: \$$ make test-php-client"
	@$(ECHO) ""
	@$(MAKE) test-server-psk

quick-test-php-psk: cert-rsa ## Test PHP client/server PSK resumption
	@$(ECHO) "$(GREEN)Quick PHP PSK test setup!$(NC)"
	@$(ECHO) "$(YELLOW)Start server in one terminal:$(NC)"
	@$(ECHO) "  \$$ make test-php-server"
	@$(ECHO) "$(YELLOW)Then run client in another:$(NC)"
	@$(ECHO) "  \$$ make test-php-client"

# PHP test
run-php: ## Run PHP test client
	@$(ECHO) "$(GREEN)Running PHP test client...$(NC)"
	@php test/manual/test_client.php

# Utility commands
show-cert-rsa: ## Display RSA server certificate details
	@$(ECHO) "$(GREEN)RSA Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout

show-cert-ec: ## Display ECC server certificate details
	@$(ECHO) "$(GREEN)ECC Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout

show-cert: show-cert-rsa ## Display server certificate details (default: RSA)

show-cert-client: ## Display client certificate details
	@$(ECHO) "$(GREEN)Client Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/client.crt -text -noout

show-cert-ca: ## Display CA certificate details
	@$(ECHO) "$(GREEN)CA Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/ca.crt -text -noout

show-commands: ## Show useful OpenSSL commands for debugging (TLS 1.3)
	@$(ECHO) "$(GREEN)Useful OpenSSL Commands for TLS 1.3 Debugging:$(NC)"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (RSA):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (ECC):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (Mutual TLS):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -CAfile $(CERT_DIR)/ca.crt -Verify 5 -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands:$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands (Mutual TLS):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -cert $(CERT_DIR)/client.crt -key $(CERT_DIR)/client.key -CAfile $(CERT_DIR)/ca.crt -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Certificate inspection:$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/client.crt -text -noout"

# Quick test scenarios
quick-test: cert-rsa ## Quick test: generate RSA cert and start server
	@$(ECHO) "$(GREEN)Quick test setup complete!$(NC)"
	@$(ECHO) "$(YELLOW)Now run in another terminal:$(NC)"
	@$(ECHO) "  \$$ make test-client"
	@$(ECHO) ""
	@$(MAKE) test-server-rsa

quick-test-ec: cert-ec ## Quick test: generate ECC cert and start server
	@$(ECHO) "$(GREEN)Quick ECC test setup complete!$(NC)"
	@$(ECHO) "$(YELLOW)Now run in another terminal:$(NC)"
	@$(ECHO) "  \$$ make test-client"
	@$(ECHO) ""
	@$(MAKE) test-server-ec

quick-test-mtls: cert-mtls ## Quick test: generate mutual TLS certs and start server
	@$(ECHO) "$(GREEN)Quick mutual TLS test setup complete!$(NC)"
	@$(ECHO) "$(YELLOW)Now run in another terminal:$(NC)"
	@$(ECHO) "  \$$ make test-client-mtls"
	@$(ECHO) ""
	@$(MAKE) test-server-mtls

quick-test-mtls-ec: cert-mtls-ec ## Quick test: generate ECC mutual TLS certs and start server
	@$(ECHO) "$(GREEN)Quick ECC mutual TLS test setup complete!$(NC)"
	@$(ECHO) "$(YELLOW)Now run in another terminal:$(NC)"
	@$(ECHO) "  \$$ make test-client-mtls-ec"
	@$(ECHO) ""
	@$(MAKE) test-server-mtls-ec

.DEFAULT_GOAL := help
