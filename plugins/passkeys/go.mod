module github.com/BladiCreator/go-modular-auth/plugins/passkeys

go 1.27.1

replace github.com/BladiCreator/go-modular-auth => ../../core

replace github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0
	github.com/go-webauthn/webauthn v0.11.2
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-webauthn/x v0.1.14 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
