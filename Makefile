build: ## Build the binary for linux
	CGO_ENABLED=0 GOARCH=amd64 go build -o ./keytool
build-mac: ## Build the binary for arm64 mac
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o ./keytool-mac