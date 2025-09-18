# TLS Craft

A PHP library for testing and controlling TLS protocol behavior.

## Overview

TLS Craft provides fine-grained control over TLS 1.3 protocol behavior for testing PHP's TLS stream implementation. It allows developers to:

- Control timing of TLS handshake messages
- Trigger KeyUpdate messages at specific intervals  
- Simulate broken client/server behaviors
- Fragment, delay, or modify TLS records
- Test edge cases and protocol violations

## Features

- Pure PHP TLS 1.3 implementation
- Fine-grained protocol control
- Integration with PHP's existing test infrastructure
- Scenario-based testing framework
- Record-level manipulation capabilities

## Requirements

- PHP 8.4+
- OpenSSL extension

## Installation

This library is intended for PHP core development and testing.
