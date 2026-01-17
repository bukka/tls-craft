<?php

namespace Php\TlsCraft\Handshake;

/**
 * TLS Extension Types Registry
 * Based on IANA TLS ExtensionType Values
 */
enum ExtensionType: int
{
    // RFC 6066
    case SERVER_NAME = 0;
    case MAX_FRAGMENT_LENGTH = 1;
    case CLIENT_CERTIFICATE_URL = 2;
    case TRUSTED_CA_KEYS = 3;
    case TRUNCATED_HMAC = 4;
    case STATUS_REQUEST = 5;

    // RFC 4681
    case USER_MAPPING = 6;

    // RFC 5878
    case CLIENT_AUTHZ = 7;
    case SERVER_AUTHZ = 8;

    // RFC 6091
    case CERT_TYPE = 9;

    // RFC 7919
    case SUPPORTED_GROUPS = 10;

    // RFC 5246
    case EC_POINT_FORMATS = 11;

    // RFC 5054
    case SRP = 12;

    // RFC 5246
    case SIGNATURE_ALGORITHMS = 13;

    // RFC 5764
    case USE_SRTP = 14;

    // RFC 6520
    case HEARTBEAT = 15;

    // RFC 7301
    case APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;

    // RFC 6961
    case STATUS_REQUEST_V2 = 17;

    // RFC 6962
    case SIGNED_CERTIFICATE_TIMESTAMP = 18;

    // RFC 7250
    case CLIENT_CERTIFICATE_TYPE = 19;
    case SERVER_CERTIFICATE_TYPE = 20;

    // RFC 7685
    case PADDING = 21;

    // RFC 7366
    case ENCRYPT_THEN_MAC = 22;

    // RFC 7627
    case EXTENDED_MASTER_SECRET = 23;

    // RFC 8449
    case RECORD_SIZE_LIMIT = 28;

    // RFC 5077
    case SESSION_TICKET = 35;

    // RFC 8446 (TLS 1.3)
    case PRE_SHARED_KEY = 41;
    case EARLY_DATA = 42;
    case SUPPORTED_VERSIONS = 43;
    case COOKIE = 44;
    case PSK_KEY_EXCHANGE_MODES = 45;
    case CERTIFICATE_AUTHORITIES = 47;
    case OID_FILTERS = 48;
    case POST_HANDSHAKE_AUTH = 49;
    case SIGNATURE_ALGORITHMS_CERT = 50;
    case KEY_SHARE = 51;

    // RFC 8879
    case COMPRESS_CERTIFICATE = 27;

    // Draft extensions (commonly used)
    case QUIC_TRANSPORT_PARAMETERS = 57;
    case ENCRYPTED_CLIENT_HELLO = 65037;

    // RFC 7507
    case RENEGOTIATION_INFO = 65281;

    // Reserved for Private Use
    case PRIVATE_USE_START = 65280;
    case PRIVATE_USE_END = 65535;

    /**
     * Get extension name for debugging/logging
     */
    public function getName(): string
    {
        return match($this) {
            self::SERVER_NAME => 'server_name',
            self::MAX_FRAGMENT_LENGTH => 'max_fragment_length',
            self::CLIENT_CERTIFICATE_URL => 'client_certificate_url',
            self::TRUSTED_CA_KEYS => 'trusted_ca_keys',
            self::TRUNCATED_HMAC => 'truncated_hmac',
            self::STATUS_REQUEST => 'status_request',
            self::USER_MAPPING => 'user_mapping',
            self::CLIENT_AUTHZ => 'client_authz',
            self::SERVER_AUTHZ => 'server_authz',
            self::CERT_TYPE => 'cert_type',
            self::SUPPORTED_GROUPS => 'supported_groups',
            self::EC_POINT_FORMATS => 'ec_point_formats',
            self::SRP => 'srp',
            self::SIGNATURE_ALGORITHMS => 'signature_algorithms',
            self::USE_SRTP => 'use_srtp',
            self::HEARTBEAT => 'heartbeat',
            self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => 'application_layer_protocol_negotiation',
            self::STATUS_REQUEST_V2 => 'status_request_v2',
            self::SIGNED_CERTIFICATE_TIMESTAMP => 'signed_certificate_timestamp',
            self::CLIENT_CERTIFICATE_TYPE => 'client_certificate_type',
            self::SERVER_CERTIFICATE_TYPE => 'server_certificate_type',
            self::PADDING => 'padding',
            self::ENCRYPT_THEN_MAC => 'encrypt_then_mac',
            self::EXTENDED_MASTER_SECRET => 'extended_master_secret',
            self::RECORD_SIZE_LIMIT => 'record_size_limit',
            self::SESSION_TICKET => 'session_ticket',
            self::COMPRESS_CERTIFICATE => 'compress_certificate',
            self::PRE_SHARED_KEY => 'pre_shared_key',
            self::EARLY_DATA => 'early_data',
            self::SUPPORTED_VERSIONS => 'supported_versions',
            self::COOKIE => 'cookie',
            self::PSK_KEY_EXCHANGE_MODES => 'psk_key_exchange_modes',
            self::CERTIFICATE_AUTHORITIES => 'certificate_authorities',
            self::OID_FILTERS => 'oid_filters',
            self::POST_HANDSHAKE_AUTH => 'post_handshake_auth',
            self::SIGNATURE_ALGORITHMS_CERT => 'signature_algorithms_cert',
            self::KEY_SHARE => 'key_share',
            self::QUIC_TRANSPORT_PARAMETERS => 'quic_transport_parameters',
            self::ENCRYPTED_CLIENT_HELLO => 'encrypted_client_hello',
            self::RENEGOTIATION_INFO => 'renegotiation_info',
            default => 'unknown_'.$this->value,
        };
    }

    /**
     * Check if extension is mandatory for TLS 1.3
     */
    public function isMandatoryForTLS13(): bool
    {
        return match($this) {
            self::SUPPORTED_VERSIONS,
            self::KEY_SHARE,
            self::SIGNATURE_ALGORITHMS => true,
            default => false,
        };
    }

    /**
     * Check if extension is allowed in specific messages
     */
    public function isAllowedInClientHello(): bool
    {
        // Most extensions are allowed in ClientHelloMessage
        return !in_array($this, [
            // Extensions that are server-only or response-only
        ]);
    }

    public function isAllowedInServerHello(): bool
    {
        return match($this) {
            self::SERVER_NAME,
            self::MAX_FRAGMENT_LENGTH,
            self::STATUS_REQUEST,
            self::USE_SRTP,
            self::HEARTBEAT,
            self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            self::SIGNED_CERTIFICATE_TIMESTAMP,
            self::EXTENDED_MASTER_SECRET,
            self::RECORD_SIZE_LIMIT,
            self::SUPPORTED_VERSIONS,
            self::KEY_SHARE => true,
            default => false,
        };
    }

    public function isAllowedInEncryptedExtensions(): bool
    {
        return match($this) {
            self::SERVER_NAME,
            self::MAX_FRAGMENT_LENGTH,
            self::SUPPORTED_GROUPS,
            self::USE_SRTP,
            self::HEARTBEAT,
            self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            self::CLIENT_CERTIFICATE_TYPE,
            self::SERVER_CERTIFICATE_TYPE,
            self::EARLY_DATA,
            self::RECORD_SIZE_LIMIT => true,
            default => false,
        };
    }
}
