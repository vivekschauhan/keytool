build: ## Build the binary for linux
	CGO_ENABLED=0 GOARCH=amd64 go build -o ./keytool