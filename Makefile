.PHONY: build
build:
	CGO_ENABLED=0 go build -o bin/gptscript-credential-sqlite -tags "${GO_TAGS}" -ldflags "-s -w" .
