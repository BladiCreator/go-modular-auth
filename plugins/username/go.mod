module github.com/BladiCreator/go-modular-auth-username

go 1.22.0

replace github.com/BladiCreator/go-modular-auth => ../../core

replace github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0
)

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
