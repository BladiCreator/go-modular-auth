module github.com/BladiCreator/go-modular-auth-polar

go 1.27.1

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/plugin-sdk v0.0.0
)

replace github.com/BladiCreator/go-modular-auth => ../../core

replace github.com/BladiCreator/go-modular-auth/plugin-sdk => ../../plugin-sdk
