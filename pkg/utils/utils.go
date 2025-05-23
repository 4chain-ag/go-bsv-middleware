package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// RequestData holds the request information used to create auth headers
type RequestData struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Request *http.Request
}

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(ctx context.Context, walletInstance interfaces.Wallet) auth.AuthMessage {
	args := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(ctx, args, "")
	if err != nil {
		panic(err)
	}

	initialNonce, err := sdkUtils.CreateNonce(ctx, walletInstance, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		panic(err)
	}

	initialRequest := auth.AuthMessage{
		Version:      auth.AUTH_VERSION,
		MessageType:  auth.MessageTypeInitialRequest,
		IdentityKey:  clientIdentityKey.PublicKey,
		InitialNonce: initialNonce,
	}

	return initialRequest
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(ctx context.Context, walletInstance interfaces.Wallet, previousResponse *auth.AuthMessage, requestData RequestData) (map[string]string, error) {
	serverIdentityKey := previousResponse.IdentityKey
	serverNonce := previousResponse.InitialNonce

	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(ctx, opts, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client identity key: %w", err)
	}

	if clientIdentityKey.PublicKey == nil {
		return nil, errors.New("client identity key is nil")
	}

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := sdkUtils.CreateNonce(ctx, walletInstance, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, fmt.Errorf("failed to create new nonce: %w", err)
	}

	var writer bytes.Buffer

	_, err = writer.Write(requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to write request ID: %w", err)
	}

	request := getOrPrepareTempRequest(requestData)
	err = WriteRequestData(request, &writer)
	if err != nil {
		return nil, fmt.Errorf("failed to write request data: %w", err)
	}

	protocol := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: serverIdentityKey,
		},
		KeyID: fmt.Sprintf("%s %s", newNonce, serverNonce),
	}
	createSignatureArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: baseArgs,
		Data:           writer.Bytes(),
	}

	signature, err := walletInstance.CreateSignature(ctx, createSignatureArgs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	headers := map[string]string{
		constants.HeaderVersion:     "0.1",
		constants.HeaderIdentityKey: clientIdentityKey.PublicKey.ToDERHex(),
		constants.HeaderNonce:       newNonce,
		constants.HeaderYourNonce:   serverNonce,
		constants.HeaderRequestID:   encodedRequestID,
	}

	if signature != nil {
		headers[constants.HeaderSignature] = hex.EncodeToString(signature.Signature.Serialize())
	}

	return headers, nil
}

// PrepareCertificateResponseHeaders prepares the certificate response headers
func PrepareCertificateResponseHeaders(ctx context.Context, walletInstance interfaces.Wallet, previousResponse *auth.AuthMessage, requestData RequestData) (map[string]string, error) {
	serverIdentityKey := previousResponse.IdentityKey
	serverNonce := previousResponse.InitialNonce

	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(ctx, opts, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client identity key: %w", err)
	}

	if clientIdentityKey.PublicKey == nil {
		return nil, fmt.Errorf("client identity key is nil")
	}

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := sdkUtils.CreateNonce(ctx, walletInstance, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, fmt.Errorf("failed to create new nonce: %w", err)
	}

	var writer bytes.Buffer

	_, err = writer.Write(requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to write request ID: %w", err)
	}

	request := getOrPrepareTempRequest(requestData)
	err = WriteRequestData(request, &writer)
	if err != nil {
		return nil, fmt.Errorf("failed to write request data: %w", err)
	}

	protocol := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: serverIdentityKey,
		},
		KeyID: fmt.Sprintf("%s %s", newNonce, serverNonce),
	}
	createSignatureArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: baseArgs,
		Data:           writer.Bytes(),
	}

	signature, err := walletInstance.CreateSignature(ctx, createSignatureArgs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	headers := map[string]string{
		constants.HeaderVersion:     "0.1",
		constants.HeaderIdentityKey: clientIdentityKey.PublicKey.ToDERHex(),
		constants.HeaderNonce:       newNonce,
		constants.HeaderYourNonce:   serverNonce,
		constants.HeaderRequestID:   encodedRequestID,
		constants.HeaderMessageType: "certificateResponse",
	}

	if signature != nil {
		headers[constants.HeaderSignature] = hex.EncodeToString(signature.Signature.Serialize())
	}

	return headers, nil
}

// WriteRequestData writes the request data into a buffer
func WriteRequestData(request *http.Request, writer *bytes.Buffer) error {
	err := WriteVarIntNum(writer, len(request.Method))
	if err != nil {
		return fmt.Errorf("failed to write method length: %w", err)
	}
	_, err = writer.Write([]byte(request.Method))
	if err != nil {
		return fmt.Errorf("failed to write method: %w", err)
	}

	err = WriteVarIntNum(writer, len(request.URL.Path))
	if err != nil {
		return fmt.Errorf("failed to write path length: %w", err)
	}
	_, err = writer.Write([]byte(request.URL.Path))
	if err != nil {
		return fmt.Errorf("failed to write path: %w", err)
	}

	query := request.URL.RawQuery
	if len(query) > 0 {
		searchAsArray := []byte(query)
		err = WriteVarIntNum(writer, len(searchAsArray))
		if err != nil {
			return fmt.Errorf("failed to write query length: %w", err)
		}
		_, err = writer.Write([]byte(query))
		if err != nil {
			return fmt.Errorf("failed to write query: %w", err)
		}
	} else {
		err = WriteVarIntNum(writer, -1)
		if err != nil {
			return fmt.Errorf("failed to write -1 as query length: %w", err)
		}
	}

	includedHeaders := ExtractHeaders(request.Header)
	err = WriteVarIntNum(writer, len(includedHeaders))
	if err != nil {
		return fmt.Errorf("failed to write headers length: %w", err)
	}

	for _, header := range includedHeaders {
		headerKeyBytes := []byte(header[0])
		err = WriteVarIntNum(writer, len(headerKeyBytes))
		if err != nil {
			return fmt.Errorf("failed to write header key length: %w", err)
		}

		_, err = writer.Write(headerKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to write header key: %w", err)
		}

		headerValueBytes := []byte(header[1])
		err = WriteVarIntNum(writer, len(headerValueBytes))
		if err != nil {
			return fmt.Errorf("failed to write header value length: %w", err)
		}

		_, err = writer.Write(headerValueBytes)
		if err != nil {
			return fmt.Errorf("failed to write header value: %w", err)
		}
	}

	err = WriteBodyToBuffer(request, writer)
	if err != nil {
		return fmt.Errorf("failed to write request body: %w", err)
	}

	return nil
}

// WriteVarIntNum writes a variable-length integer to a buffer
// integer is converted to fixed size int64
func WriteVarIntNum(writer *bytes.Buffer, num int) error {
	err := binary.Write(writer, binary.LittleEndian, int64(num))
	if err != nil {
		return fmt.Errorf("failed to write varint number: %w", err)
	}
	return nil
}

// ReadVarIntNum reads a variable-length integer from a buffer
func ReadVarIntNum(reader *bytes.Reader) (int64, error) {
	var intByte int64
	err := binary.Read(reader, binary.LittleEndian, &intByte)
	if err != nil {
		return 0, fmt.Errorf("failed to read varint number: %w", err)
	}

	return intByte, nil
}

// ExtractHeaders extracts required headers based on conditions
func ExtractHeaders(headers http.Header) [][]string {
	var includedHeaders [][]string
	for k, v := range headers {
		k = strings.ToLower(k)
		if (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
			!strings.HasPrefix(k, constants.AuthHeaderPrefix) {
			includedHeaders = append(includedHeaders, []string{k, v[0]})
		}
	}
	return includedHeaders
}

// WriteBodyToBuffer writes the request body into a buffer
func WriteBodyToBuffer(req *http.Request, buf *bytes.Buffer) error {
	if req.Body == nil {
		err := WriteVarIntNum(buf, -1)
		if err != nil {
			return fmt.Errorf("failed to write -1 for empty body: %w", err)
		}
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	if len(body) > 0 {
		err = WriteVarIntNum(buf, len(body))
		if err != nil {
			return fmt.Errorf("failed to write body length: %w", err)
		}

		_, err = buf.Write(body)
		if err != nil {
			return fmt.Errorf("failed to write body: %w", err)
		}

		return nil
	}

	err = WriteVarIntNum(buf, -1)
	if err != nil {
		return fmt.Errorf("failed to write -1 for empty body: %w", err)
	}
	return nil
}

func generateRandom() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func getOrPrepareTempRequest(requestData RequestData) *http.Request {
	if requestData.Request != nil {
		return requestData.Request
	}

	req, err := http.NewRequest(requestData.Method, requestData.URL, bytes.NewBuffer(requestData.Body))
	if err != nil {
		panic(err)
	}

	for key, value := range requestData.Headers {
		req.Header.Set(key, value)
	}

	return req
}
