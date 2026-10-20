.DEFAULT_GOAL := test

.PHONY: test test-race bench lint tidy work-sync vet clean

test:
	go test ./...

test-race:
	go test -race ./...

bench:
	go test -bench=. -benchmem -run=^# ./...

vet:
	go vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint is not installed, running go vet instead"; \
		go vet ./...; \
	fi

tidy:
	go mod tidy
	go work sync

work-sync:
	go work sync

clean:
	go clean -cache -testcache
