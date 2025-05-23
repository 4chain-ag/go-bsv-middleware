# Go BSV Middleware Examples

This directory contains examples demonstrating how to use the Go BSV Middleware library for implementing Bitcoin SV blockchain authentication and payment protocols.

## Overview

The Go BSV Middleware implements [BRC-103](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0103.md) (Peer-to-Peer Mutual Authentication and Certificate Exchange Protocol) and [BRC-104](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0104.md) (HTTP Transport for BRC-103 Mutual Authentication) specifications, providing a robust authentication middleware layer for Go applications.

The examples are organized into the following sections:

- [Authentication Examples](#authentication-examples) - Demonstrate BRC-103/104 mutual authentication
- [Payment Examples](#payment-examples) - Showcase the Direct Payment Protocol (DPP) for micropayments

## Dependencies

These examples depend on:
- Go 1.24 or higher
- github.com/bsv-blockchain/go-bsv-middleware
- github.com/bsv-blockchain/go-sdk


## Authentication Examples

The authentication examples demonstrate how to implement BRC-103/104 for mutual authentication between clients and servers.

### Basic Authentication Example

Located in
```
examples/auth/basic/
└── auth.go           # Complete example of basic mutual authentication
```

This example demonstrates:
- Server setup with auth middleware
- Client authentication handshake
- Authenticated request/response flow
- Header and signature verification

#### Key Features

- **Mutual Authentication**: Both client and server authenticate each other
- **Session Management**: Server stores and validates client sessions
- **Header-Based Authentication**: Uses HTTP headers for authentication data
- **Cryptographic Verification**: Validates signatures and nonces

#### Running the Example

```bash
cd auth/basic
go run auth.go
```

The output will show each step of the authentication process:

1. Creating wallet instances for both server and client
2. Setting up the authentication middleware
3. Performing the initial handshake request to `/.well-known/auth`
4. Making an authenticated general request to verify the authentication works

### Certificate Authentication Example

Located in `auth/certificate/`, this example demonstrates a more advanced authentication flow with certificate verification:

```
examples/auth/certificate/
└── certificate.go    # Complete example of certificate-based authentication
```

This example shows:
- Age verification using certificates
- Certificate request/response process
- Validation of certificate fields
- Access control based on certificate contents

#### Key Features

- **Certificate Exchange**: Server requests specific certificates from clients
- **Field Verification**: Server validates certificate field values (e.g., age ≥ 18)
- **Attribute-Based Access Control**: Access decisions based on certificate attributes
- **Trusted Certifiers**: Validation of certificate issuers

#### Running the Example

```bash
cd auth/certificate
go run certificate.go
```

The output will demonstrate:
1. Initial authentication handshake
2. Server requesting certificates
3. Client sending a certificate
4. Server validating the certificate and granting access

## Payment Examples

The payment examples demonstrate the Direct Payment Protocol (DPP) for Bitcoin SV micropayments.

### Basic Payment Example

Located in `payment/basic/`, this example shows how to implement the payment protocol:

```
examples/payment/basic/
├── README.md         # Detailed explanation of the payment flow
├── client/           # Client implementation for payments
│   └── client.go     
└── server/           # Server that handles payments
    └── server.go     
```

This example demonstrates:
- Authentication combined with payments
- Free vs. paid API endpoints
- 402 Payment Required flow
- Payment verification and processing

#### Key Features

- **Direct Payment Protocol**: Implementation of BSV micropayments
- **402 Payment Flow**: Proper HTTP status codes and payment terms
- **Payment Verification**: Transaction validation before resource access
- **Mixed Endpoint Types**: Combining free and paid resources in one API

#### Running the Example

```bash
# Start the server in one terminal
cd payment/basic/server
go run server.go

# Run the client in another terminal
cd payment/basic/client
go run client.go
```

## Example Wallet Implementation

An example wallet implementation is provided in `example-wallet/` to facilitate the examples:

```
examples/example-wallet/
├── example_wallet.go # Implementation of the wallet interface
└── key_deriver.go    # Key derivation utilities
```

This wallet implementation provides:
- Cryptographic key generation and derivation
- Signing and verification capabilities
- Certificate operations
- HMAC creation and verification
