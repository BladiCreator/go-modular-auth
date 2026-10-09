module github.com/BladiCreator/go-modular-auth-audit

go 1.22.0

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0
)

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/BladiCreator/go-modular-auth => ../../core

replace github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk
