# Pillager

![Image](./images/brand_image_ice.png)

[![Go Report Card](https://goreportcard.com/badge/github.com/brittonhayes/pillager)](https://goreportcard.com/report/github.com/brittonhayes/pillager)

![Latest Release](https://img.shields.io/github/v/release/brittonhayes/pillager?label=latest%20release)

## Table of Contents

1. [Summary](#summary)
1. [Installation](#installation)
1. [Usage](#usage)
1. [Documentation](#documentation)

## Summary

Pillager is designed to provide a simple means of leveraging Go's strong concurrency model to recursively search directories for sensitive information in files. Pillager does this by standing on the shoulders of [a few giants](#shoulders-of-giants). Once pillager finds files that match the specified pattern, the file is scanned using a series of concurrent workers that each take a line of the file from the job queue and hunt for sensitive pattern matches. The available pattern filters can be found in the `hunt` command's help page.

## Installation

### Go

If you have Go setup on your system, you can install Pillager with `go get`
 
```shell script
go get github.com/brittonhayes/pillager
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

If you're looking for a binary, check the latest releases for the executable that matches your system

## Usage

To see all the commands available with `pillager`

```shell
# To see instructions for the entire application
pillager

# From any subcommand
pillager [cmd] --help
```

## Configuration

### Gitleaks Rules

Pillager provides full support for [Gitleaks](https://github.com/zricethezav/gitleaks) rules. This can either be passed in with a [rules.toml](./rules.toml) file, or you can use the default ruleset by leaving the rules flag blank. 

> Currently entropy is not implemented, but it is absolutely planned to add support for Gitleaks' entropy configs in future updates.

```toml
# rules.toml
title = "pillager rules"
[[rules]]
description = "AWS Access Key"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
tags = ["key", "AWS"]
[[rules]]
description = "Email Address"
regex = '''(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)'''
tags = ["email", "User Info"]
```

## Documentation

:books: [View the docs](./pkg/hunter)

GoDoc documentation is available on [pkg.go.dev for pillager](https://pkg.go.dev/github.com/brittonhayes/pillager) but it also available for all packages in the [./pkg](./pkg) directory. 
Just open the folder of any package and you'll see the GoDocs rendered in beautiful Github-flavored markdown thanks to the awesome [gomarkdoc](https://github.com/princjef/gomarkdoc) tool.

---

### Shoulders of Giants :star:

#### [afero's regexpFs](https://github.com/spf13/afero#regexpfs). 

**What is RegexpFs?**

> A filtered view on file names, any file NOT matching the provided patterns will be treated as non-existing.

This is important because it limits the number of files being scanned in the first place, thus cutting down on the time to finish the scan. In other words, we probably don't want to attempt to scan a `*.mp4` from top to bottom, but we definitely _do_ want to scan a `*.env` from top to bottom.

#### [afero's Cobra](https://github.com/spf13/cobra)

**What is Cobra?**

> Cobra is a library providing a simple interface to create powerful modern CLI interfaces similar to git & go tools. Cobra is also an application that will generate your application scaffolding to rapidly develop a Cobra-based application.

If you've seen a CLI written in Go before, there's a pretty high chance it was built with Cobra. I can't recommend this library enough. It empowers developers to make consistent, dynamic, and self-documenting command line tools with ease. Some examples include `kubectl`, `hugo`, and Github's `gh` CLI.

#### [Gitleaks](https://github.com/zricethezav/gitleaks)

**What is Gitleaks?**

> Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.

Gitleaks is an amazing tool for secret leak prevention. If you haven't implemented Gitleaks as a pre-commit checker, it's worth your time to check it out. 

**Why is Gitleaks relevant to Pillager?**

Pillager implements the powerful [rules](https://github.com/zricethezav/gitleaks#rules-summary) functionality of Gitleaks while taking a more offensive approach to working with the secrets found. 
While I have provided a baseline set of default rules, Pillager becomes much more powerful if you allow users to create rules for their own use-cases.

---

> This goes without saying but I'm going to say it anyways: I am **not** responsible for any repercussions caused by your use of pillager. This tool is intended for defensive, Blue Team use.
