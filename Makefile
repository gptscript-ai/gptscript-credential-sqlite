.PHONY: build-sqlite
build-sqlite:
	CGO_ENABLED=0 go build -o bin/gptscript-credential-sqlite -tags "${GO_TAGS}" -ldflags "-s -w" ./sqlite

.PHONY: build-postgres
build-postgres:
	CGO_ENABLED=0 go build -o bin/gptscript-credential-postgres -tags "${GO_TAGS}" -ldflags "-s -w" ./postgres

.PHONY: build
build: build-sqlite build-postgres
