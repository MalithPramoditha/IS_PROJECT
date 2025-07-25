# Secure Chat Application

A secure text-based chat system implementing:

- Password-based authentication with PBKDF2 hashing
- End-to-end encryption using RSA + AES-GCM
- Message integrity and replay protection with timestamps
- Mutual identity verification using public key fingerprints
- Audit logging of authentication events
- Forward secrecy via ephemeral ECDH key exchange
- AES session key rotation for added security

## Features

- User authentication with strong password hashing
- Secure RSA key exchange and AES session keys for message encryption
- AES-GCM provides confidentiality and message integrity
- Replay attack prevention using timestamps
- Identity verification by exchanging and comparing public key fingerprints
- Authentication event logging for audit purposes
- Forward secrecy using ephemeral Diffie-Hellman (ECDH) key agreement
- Scheduled key rotation for session keys

## Getting Started

### Prerequisites

- Java 11 or higher
- Maven or other Java build tools (optional)

### How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-chat-app.git
   cd secure-chat-app
