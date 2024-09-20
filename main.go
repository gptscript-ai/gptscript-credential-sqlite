package main

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/gptscript-ai/gptscript-helper-sqlite/pkg/sqlite"
)

func main() {
	s, err := sqlite.NewSqlite(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error creating sqlite: %v\n", err)
		os.Exit(1)
	}
	credentials.Serve(s)
}
