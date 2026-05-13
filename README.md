# Secure TLS Client

A secure TLS client written in C using OpenSSL that establishes encrypted connections, validates server certificates, and enforces strict security verification rules. The client was developed as part of a secure coding and systems programming project focused on TLS communication and certificate authentication.

# Project Overview

This project simulates how secure client applications establish trusted TLS connections over a network. The client connects to a server, performs a TLS handshake, validates the server’s certificate chain, checks certificate expiration dates, and verifies that the server’s Common Name (CN) matches the expected identity.

# The program demonstrates core cybersecurity and networking concepts including:

- TLS handshakes
- Certificate verification
- Trusted root CA validation
- Secure socket programming
- OpenSSL integration
- Defensive programming practices
  
# Features

- 🔒 Establishes secure TLS connections using OpenSSL
- ✅ Verifies certificates against trusted root Certificate Authorities
- ⏰ Detects expired or invalid certificates
- 🛡 Validates the server Common Name (CN)
- 📡 Connects using TCP sockets
- ⚡ Supports TLS 1.2+
- 🧠 Includes detailed error handling and validation logic
- Security Checks Performed

# The client validates:

1. Certificate is signed by a trusted root CA
2. Certificate validity period is current
3. Server Common Name matches the expected server identity

If any validation fails, the client terminates and prints a security error message.

# Technologies Used
- Language: C
- Libraries: OpenSSL
- Concepts: TLS, Networking, Secure Coding, Certificate Validation
- Environment: Linux / macOS

# Running the Client
./tls_client <server_ip>  <port>

# Example Outputs
Successful Connection
"Hello from TLS Server"

Certificate CN Mismatch
"ERROR: certificate CN mismatch"
(found: Secure Coding TLS Server)

Untrusted Root CA
ERROR: certificate not signed by trusted root CA
