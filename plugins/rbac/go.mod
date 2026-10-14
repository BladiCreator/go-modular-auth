module github.com/BladiCreator/go-modular-auth-rbac

go 1.27.1

replace github.com/BladiCreator/go-modular-auth => ../../core

replace github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk

replace github.com/BladiCreator/go-modular-auth/adapters/memory => ../../adapters/memory

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
