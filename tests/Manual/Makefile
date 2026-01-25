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

# PSK Configuration
PSK_IDENTITY = my-test-psk
PSK_KEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Color output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

SHELL := /bin/bash
.SHELLFLAGS := -ec
ECHO := echo -e

.DEFAULT_GOAL := help

.PHONY: help clean init all

help: ## Show this help message
	@$(ECHO) "$(GREEN)OpenSSL TLS 1.3 Testing Makefile$(NC)"
	@$(ECHO) "$(YELLOW)Usage:$(NC) make [target]"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-40s$(NC) %s\n", $$1, $$2}'

all: cert-rsa cert-ec ## Generate RSA and ECC certificates

init: ## Initialize certificate directory
	@$(ECHO) "$(YELLOW)Creating certificate directory...$(NC)"
	@mkdir -p $(CERT_DIR)

clean: ## Clean all generated certificates
	@$(ECHO) "$(RED)Cleaning certificates...$(NC)"
	@rm -rf $(CERT_DIR)

# ==============================================================================
# Certificate Generation
# ==============================================================================

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

# Legacy alias
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

# ==============================================================================
# OpenSSL Test Servers - Basic Certificate Authentication
# ==============================================================================

test-server: test-server-rsa ## Start OpenSSL s_server (default: RSA)

test-server-rsa: ## Start OpenSSL s_server with RSA certificate (TLS 1.3)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, RSA) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug -rev"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug -rev

test-server-ec: ## Start OpenSSL s_server with ECC certificate (TLS 1.3)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug -rev"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug -rev

test-server-ec-verbose: ## Start OpenSSL s_server (TLS 1.3) with verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -rev -state"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -rev -state

test-server-verbose: ## Start OpenSSL s_server (TLS 1.3) with verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -rev -state"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -debug -tlsextdebug -security_debug_verbose -msg -rev -state

test-server-groups: ## Start OpenSSL s_server (TLS 1.3) with specific groups
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with groups) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -groups X25519:P-256:P-384 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -groups X25519:P-256:P-384 -debug

test-server-ciphersuites: ## Start OpenSSL s_server (TLS 1.3) with specific cipher suites
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3 with cipher suites) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug"
	@$(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -debug

# ==============================================================================
# OpenSSL Test Servers - Mutual TLS
# ==============================================================================

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

# ==============================================================================
# OpenSSL Test Servers - Session Resumption
# ==============================================================================

test-server-psk: ## Start OpenSSL s_server with session resumption support
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, session resumption) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports session resumption$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -debug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 -debug -state -msg -rev

test-server-psk-ec: ## Start OpenSSL s_server with session resumption (ECC)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, session resumption, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports session resumption$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -debug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 -debug -state -msg -rev

test-server-psk-verbose: ## Start OpenSSL s_server with session resumption and verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, session resumption verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -keylogfile $(CERT_DIR)/server.keylog -debug -tlsextdebug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 \
		-keylogfile $(CERT_DIR)/server.keylog \
		-debug -tlsextdebug -state -msg -rev

test-server-psk-ec-verbose: ## Start OpenSSL s_server with session resumption and verbose output (ECC)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, session resumption verbose, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -keylogfile $(CERT_DIR)/server.keylog -debug -tlsextdebug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 \
		-keylogfile $(CERT_DIR)/server.keylog \
		-debug -tlsextdebug -state -msg -rev

# ==============================================================================
# OpenSSL Test Servers - External PSK
# ==============================================================================

test-server-external-psk: ## Start OpenSSL s_server with external PSK (no cert)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, External PSK) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -nocert -tls1_3 -debug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-nocert \
		-tls1_3 -debug -state -msg -rev

test-server-external-psk-ec: ## Start OpenSSL s_server with external PSK + ECC cert
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, External PSK + ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Note: Server has ECC cert but will prefer PSK if client offers it$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -debug -state -msg -rev

test-server-external-psk-verbose: ## Start OpenSSL s_server with external PSK and verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, External PSK verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -nocert -tls1_3 -keylogfile $(CERT_DIR)/server-psk.keylog -debug -tlsextdebug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-nocert \
		-keylogfile $(CERT_DIR)/server-psk.keylog \
		-tls1_3 -debug -tlsextdebug -state -msg -rev

test-server-external-psk-ec-verbose: ## Start OpenSSL s_server with external PSK + ECC and verbose output
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, External PSK + ECC verbose) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -keylogfile $(CERT_DIR)/server-psk.keylog -debug -tlsextdebug -state -msg -rev"
	@$(OPENSSL) s_server -accept $(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-keylogfile $(CERT_DIR)/server-psk.keylog \
		-tls1_3 -debug -tlsextdebug -state -msg -rev

# ==============================================================================
# OpenSSL Test Servers - Early Data (0-RTT)
# ==============================================================================

test-server-early-data: test-server-early-data-rsa

test-server-external-psk-early-data: ## Start OpenSSL s_server with external PSK and early data
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, External PSK, Early Data) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data with PSK$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -nocert -keylogfile $(CERT_DIR)/server.keylog -tls1_3 -early_data -max_early_data 16384 -debug -tlsextdebug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-nocert \
		-keylogfile $(CERT_DIR)/server.keylog \
		-tls1_3 -early_data -max_early_data 16384 \
		-debug -tlsextdebug -state -msg

test-server-early-data-rsa:
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Early Data, RSA) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -early_data -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 -early_data \
		-debug -state -msg

test-server-early-data-ec:
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Early Data, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -early_data -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 -early_data \
		-debug -state -msg

test-server-early-data-verbose: ## Start OpenSSL s_server with early data and verbose output (RSA)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Early Data verbose, RSA) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -early_data -keylogfile $(CERT_DIR)/server.keylog -debug -tlsextdebug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key \
		-tls1_3 -num_tickets 2 -early_data \
		-keylogfile $(CERT_DIR)/server.keylog \
		-debug -tlsextdebug -state -msg

test-server-early-data-ec-verbose: ## Start OpenSSL s_server with early data and verbose output (ECC)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Early Data verbose, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -early_data -keylogfile $(CERT_DIR)/server.keylog -debug -tlsextdebug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 -early_data \
		-keylogfile $(CERT_DIR)/server.keylog \
		-debug -tlsextdebug -state -msg

test-server-early-data-anti-replay: ## Start OpenSSL s_server with early data and anti-replay (ECC)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, Early Data + Anti-Replay, ECC) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server supports 0-RTT early data with anti-replay protection$(NC)"
	@$(ECHO) "$(YELLOW)Note: Anti-replay will reject duplicate early data$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -early_data -anti_replay -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 -early_data -anti_replay \
		-debug -state -msg

test-server-early-data-reject: ## Start OpenSSL s_server that rejects early data (for testing rejection)
	@$(ECHO) "$(GREEN)Starting OpenSSL s_server (TLS 1.3, NO Early Data) on port $(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Server will REJECT early data (for testing rejection handling)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -num_tickets 2 -debug -state -msg"
	@$(OPENSSL) s_server -accept $(PORT) \
		-cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key \
		-tls1_3 -num_tickets 2 \
		-debug -state -msg

# ==============================================================================
# OpenSSL Test Clients - Basic
# ==============================================================================

test-client: ## Connect with OpenSSL s_client (TLS 1.3)
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts

test-client-verbose: ## Connect with OpenSSL s_client (TLS 1.3) with verbose output
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 verbose) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg -groups P-256 -keylogfile $(CERT_DIR)/client.keylog"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg -groups P-256 -keylogfile $(CERT_DIR)/client.keylog

test-client-groups: ## Connect with OpenSSL s_client (TLS 1.3) with specific groups
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3 with groups) to $(HOST):$(PORT)...$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -groups X25519:P-256 -showcerts

# ==============================================================================
# OpenSSL Test Clients - Mutual TLS
# ==============================================================================

test-client-mtls: ## Connect with OpenSSL s_client using client certificate
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

# ==============================================================================
# OpenSSL Test Clients - Session Resumption
# ==============================================================================

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

# ==============================================================================
# OpenSSL Test Clients - External PSK
# ==============================================================================

test-client-external-psk: ## Connect with OpenSSL s_client using external PSK
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, External PSK)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -tls1_3 -showcerts"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) \
		-psk $(PSK_KEY) \
		-psk_identity $(PSK_IDENTITY) \
		-tls1_3 -showcerts

test-client-external-psk-verbose: ## Connect with OpenSSL s_client using external PSK with verbose output
	@$(ECHO) "$(GREEN)Connecting with OpenSSL s_client (TLS 1.3, External PSK verbose)...$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) $(OPENSSL) s_client -connect $(HOST):$(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -tls1_3 -keylogfile $(CERT_DIR)/client-psk.keylog -debug -state -msg"
	@$(OPENSSL) s_client -connect $(HOST):$(PORT) \
		-psk $(PSK_KEY) \
		-psk_identity $(PSK_IDENTITY) \
		-keylogfile $(CERT_DIR)/client-psk.keylog \
		-tls1_3 -debug -state -msg

# ==============================================================================
# OpenSSL Test Clients - Early Data (0-RTT)
# ==============================================================================

test-client-openssl-psk-early-data: ## Test with OpenSSL s_client using PSK and early data against PHP server
	@$(ECHO) "$(GREEN)Testing with OpenSSL s_client (PSK + Early Data)...$(NC)"
	@$(ECHO) "$(YELLOW)Make sure PHP server is running: php tests/Manual/server_early_data.php$(NC)"
	@$(ECHO) "$(YELLOW)PSK Identity: $(PSK_IDENTITY)$(NC)"
	@$(ECHO) "$(YELLOW)PSK Key: $(PSK_KEY)$(NC)"
	@$(ECHO) "$(YELLOW)Early Data: GET / HTTP/1.1$(NC)"
	@$(ECHO) "$(YELLOW)Command:$(NC) echo 'follow-up message' | $(OPENSSL) s_client -connect localhost:$(PORT) -psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) -tls1_3 -early_data early_data.txt -keylogfile $(CERT_DIR)/client.keylog -debug -tlsextdebug -state -msg"
	@echo "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > early_data.txt
	@echo "follow-up message" | $(OPENSSL) s_client -connect localhost:$(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-tls1_3 -early_data early_data.txt \
		-keylogfile $(CERT_DIR)/client.keylog \
		-debug -tlsextdebug -state -msg
	@rm -f early_data.txt

test-client-openssl-session-early-data: ## Test OpenSSL s_client with session resumption and early data
	@$(ECHO) "$(GREEN)Testing with OpenSSL s_client (Session Resumption + Early Data)...$(NC)"
	@$(ECHO) "$(YELLOW)Make sure PHP server is running: php tests/Manual/server_early_data.php$(NC)"
	@$(ECHO) ""
	@$(ECHO) "$(CYAN)Step 1: Initial connection to get session ticket...$(NC)"
	@echo "first connection" | $(OPENSSL) s_client -connect localhost:$(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-tls1_3 -sess_out session.pem \
		-keylogfile $(CERT_DIR)/client.keylog \
		-ign_eof
	@$(ECHO) ""
	@$(ECHO) "$(CYAN)Step 2: Resumption with 0-RTT early data...$(NC)"
	@echo "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > early_data.txt
	@echo "follow-up message" | $(OPENSSL) s_client -connect localhost:$(PORT) \
		-psk $(PSK_KEY) -psk_identity $(PSK_IDENTITY) \
		-tls1_3 -sess_in session.pem \
		-early_data early_data.txt \
		-keylogfile $(CERT_DIR)/client.keylog
	@rm -f early_data.txt session.pem

# ==============================================================================
# PHP Test Scripts
# ==============================================================================

test-php-server: ## Run PHP TLS server
	@$(ECHO) "$(GREEN)Starting PHP TLS server on port $(PORT)...$(NC)"
	@php test/manual/test_server.php

test-php-client: ## Run PHP TLS client
	@$(ECHO) "$(GREEN)Running PHP TLS client connecting to $(HOST):$(PORT)...$(NC)"
	@php test/manual/test_client.php

test-php-client-native: ## Run native PHP TLS client (stream_socket_client)
	@$(ECHO) "$(GREEN)Running native PHP TLS client connecting to $(HOST):$(PORT)...$(NC)"
	@php test/manual/test_client_native.php

run-php: test-php-client ## Run PHP test client (alias)

# ==============================================================================
# Utility Commands
# ==============================================================================

show-cert: show-cert-rsa ## Display server certificate details (default: RSA)

show-cert-rsa: ## Display RSA server certificate details
	@$(ECHO) "$(GREEN)RSA Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout

show-cert-ec: ## Display ECC server certificate details
	@$(ECHO) "$(GREEN)ECC Server Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout

show-cert-client: ## Display client certificate details
	@$(ECHO) "$(GREEN)Client Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/client.crt -text -noout

show-cert-ca: ## Display CA certificate details
	@$(ECHO) "$(GREEN)CA Certificate Details:$(NC)"
	@$(OPENSSL) x509 -in $(CERT_DIR)/ca.crt -text -noout

generate-psk-key: ## Generate a random 256-bit PSK key
	@$(ECHO) "$(GREEN)Generating random 256-bit PSK key:$(NC)"
	@$(OPENSSL) rand -hex 32
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)To use this key:$(NC)"
	@$(ECHO) "  1. Copy the hex string above"
	@$(ECHO) "  2. Set PSK_KEY variable in Makefile or environment"
	@$(ECHO) "  3. Make sure both client and server use the same key"

show-commands: ## Show useful OpenSSL commands for debugging (TLS 1.3)
	@$(ECHO) "$(GREEN)Useful OpenSSL Commands for TLS 1.3 Debugging:$(NC)"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (RSA):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (ECC):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_ec.crt -key $(CERT_DIR)/server_ec.key -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (External PSK):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -psk 0123456789abcdef... -nocert -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (Mutual TLS):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key -CAfile $(CERT_DIR)/ca.crt -Verify 5 -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Server commands (Session Resumption):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_server -accept $(PORT) -cert $(CERT_DIR)/server_rsa.crt -key $(CERT_DIR)/server_rsa.key -tls1_3 -num_tickets 2 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands:$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -showcerts"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -debug -msg"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands (External PSK):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -psk 0123456789abcdef... -psk_identity test-psk -tls1_3 -showcerts"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands (Mutual TLS):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -cert $(CERT_DIR)/client.crt -key $(CERT_DIR)/client.key -CAfile $(CERT_DIR)/ca.crt -tls1_3 -debug"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Client commands (Session Resumption):$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_out $(CERT_DIR)/session.pem"
	@$(ECHO) "  \$$ $(OPENSSL) s_client -connect $(HOST):$(PORT) -tls1_3 -sess_in $(CERT_DIR)/session.pem"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)Certificate inspection:$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/server_rsa.crt -text -noout"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/server_ec.crt -text -noout"
	@$(ECHO) "  \$$ $(OPENSSL) x509 -in $(CERT_DIR)/client.crt -text -noout"
	@$(ECHO) ""
	@$(ECHO) "$(YELLOW)PSK key generation:$(NC)"
	@$(ECHO) "  \$$ $(OPENSSL) rand -hex 32"
