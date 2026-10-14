module github.com/BladiCreator/go-modular-auth/plugins/sso

go 1.27.1

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugins/organizations v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/BladiCreator/go-modular-auth => ../../core
	github.com/BladiCreator/go-modular-auth/plugins/organizations => ../organizations
	github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk
)
