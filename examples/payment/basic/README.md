# BSV Payment Middleware Example

This example demonstrates the Direct Payment Protocol (DPP) using the Go BSV middleware library. It shows a complete payment flow from authentication to payment verification and resource access.

## Overview

This example includes:

- `server.go` - HTTP server with both free and paid endpoints
- `client.go` - Client that demonstrates authentication and payment flows

## Requirements

- Go 1.24 or higher
- The `go-bsv-middleware` package and its dependencies

## Running the Example

### 1. Start the Server

```bash
cd server && go run server.go
```

This starts a server on port 8080 with two endpoints:

- `/info` - Free endpoint (authentication only)
- `/premium` - Paid endpoint (10 satoshis)

### 2. Run the Client

In a separate terminal:

```bash
cd client && go run client.go
```

## Complete Payment Flow

The client walks through the complete DPP payment flow:

1. **Authentication**: Client authenticates with the server using BRC-103/104
2. **Free Endpoint**: Client accesses the free endpoint that only requires authentication
3. **Initial Paid Request**: Client requests `/premium`, receives a 402 Payment Required response
4. **Payment Preparation**: Client processes the payment terms and creates a payment transaction
5. **Payment Submission**: Client submits the payment and retrieves the premium content

## Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: Authentication (BRC-103/104)
    Server-->>Client: Authentication Response

    Client->>Server: Request /info
    Server-->>Client: Free Info Response

    Client->>Server: Request /premium
    Server-->>Client: 402 Payment Required + Terms

    Client->>Server: Request with Payment Header
    Server-->>Client: Premium Data Response

## Key DPP Concepts Demonstrated

1. **402 Payment Required**: Server responds with 402 status code and payment terms when payment is needed
2. **Payment Terms**: Structured JSON object containing payment requirements
3. **Payment Modes**: Using the "bsv-direct" payment mode
4. **Derivation Prefix/Suffix**: Used to securely generate payment addresses
5. **Standard Headers**: Using `X-BSV-Payment` headers for payment data
6. **Payment Verification**: Server verifies the payment before providing access to resources
7. **Free Endpoints**: Mix of paid and free endpoints in the same API
