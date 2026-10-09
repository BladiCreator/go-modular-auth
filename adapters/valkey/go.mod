module github.com/BladiCreator/go-modular-auth/adapters/valkey

go 1.26.0

require (
	github.com/BladiCreator/go-modular-auth v0.0.0
	github.com/BladiCreator/go-modular-auth/adapters/redis v0.0.0
)

replace (
	github.com/BladiCreator/go-modular-auth => ../../core
	github.com/BladiCreator/go-modular-auth/adapters/redis => ../redis
)
