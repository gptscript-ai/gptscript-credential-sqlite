package common

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
)

// uid is here to fulfill the value.Context interface for the transformer.
// This is similar to authenticatedDataString from the k8s apiserver's storage interface
// for etcd: https://github.com/kubernetes/kubernetes/blob/a42f4f61c2c46553bfe338eefe9e81818c7360b4/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L63
type uid string

func (u uid) AuthenticatedData() []byte {
	return []byte(u)
}

var GroupResource = schema.GroupResource{
	Group:    "", // deliberately left empty
	Resource: "credentials",
}

type Database struct {
	db          *gorm.DB
	transformer value.Transformer
}

func NewDatabase(ctx context.Context, db *gorm.DB) (Database, error) {
	if err := db.AutoMigrate(&GptscriptCredential{}); err != nil {
		return Database{}, fmt.Errorf("failed to auto migrate GptscriptCredential: %w", err)
	}

	encryptionConf, err := readEncryptionConfig(ctx)
	if err != nil {
		return Database{}, fmt.Errorf("failed to read encryption config: %w", err)
	} else if encryptionConf != nil {
		transformer, exists := encryptionConf.Transformers[GroupResource]
		if !exists {
			return Database{}, fmt.Errorf("failed to find encryption transformer for %s", GroupResource.String())
		}
		return Database{
			db:          db,
			transformer: transformer,
		}, nil
	}

	return Database{
		db: db,
	}, nil
}

func NewDatabaseWithTransformer(db *gorm.DB, transformer value.Transformer) Database {
	return Database{
		db:          db,
		transformer: transformer,
	}
}

type GptscriptCredential struct {
	ID        uint `gorm:"primary_key"`
	CreatedAt time.Time
	ServerURL string `gorm:"unique"`
	Username  string
	Secret    string
}

func (s Database) Add(creds *credentials.Credentials) error {
	cred := GptscriptCredential{
		ServerURL: creds.ServerURL,
		Username:  creds.Username,
		Secret:    creds.Secret,
	}

	cred, err := s.encryptCred(context.Background(), cred)
	if err != nil {
		return fmt.Errorf("failed to encrypt credential: %w", err)
	}

	// First, we need to check if a credential with this serverURL already exists.
	// If it does, delete it first.
	// This would normally happen during a credential refresh.
	var existing GptscriptCredential
	if err := s.db.Where("server_url = ?", cred.ServerURL).First(&existing).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to get existing credential: %w", err)
		}
	} else {
		if err := s.db.Delete(&existing).Error; err != nil {
			return fmt.Errorf("failed to delete existing credential: %w", err)
		}
	}

	if err := s.db.Create(&cred).Error; err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

func (s Database) Delete(serverURL string) error {
	var (
		cred GptscriptCredential
		err  error
	)
	if err = s.db.Where("server_url = ?", serverURL).Delete(&cred).Error; err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

func (s Database) Get(serverURL string) (string, string, error) {
	var (
		cred GptscriptCredential
		err  error
	)
	if err = s.db.Where("server_url = ?", serverURL).First(&cred).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("failed to get credential: %w", err)
	}

	cred, err = s.decryptCred(context.Background(), cred)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt credential: %w", err)
	}

	return cred.Username, cred.Secret, nil
}

func (s Database) List() (map[string]string, error) {
	var (
		creds []GptscriptCredential
		err   error
	)
	if err = s.db.Find(&creds).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	credMap := make(map[string]string)
	for _, cred := range creds {
		// No need to decrypt anything, since we don't need to access the secret.
		credMap[cred.ServerURL] = cred.Username
	}

	return credMap, nil
}
