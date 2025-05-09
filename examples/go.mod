module github.com/bsv-blockchain/go-bsv-middleware-examples

go 1.24.0

require (
	github.com/bsv-blockchain/go-bsv-middleware v0.4.0
	github.com/bsv-blockchain/go-sdk v1.1.23
	github.com/go-resty/resty/v2 v2.16.5
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// TODO: remove this when the module is published
// Temporary until we publish the module in stable version
replace github.com/bsv-blockchain/go-bsv-middleware => ../

replace github.com/bsv-blockchain/go-sdk => ../../gorilla/go-sdk
