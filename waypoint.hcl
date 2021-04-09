project = "pillager"

app "cli" {

  labels = {
    "maintainer" = "Britton Hayes"
    "github" = "https://github.com/brittonhayes/pillager"
  }

  build {
    use "docker" {}

    registry {
      use "docker" {
        image = "bjhayes/pillager"
        tag = "latest"
      }
    }
    hook {
      when = "before"
      command = [
        "golangci-lint",
        "run",
        "./..."]
      on_failure = "fail"
    }

    hook {
      when = "before"
      command = [
        "go",
        "test",
        "-v",
        "./..."]
      on_failure = "fail"
    }
  }

  deploy {
    use "docker" {}
  }

  url {
    auto_hostname = false
  }
}
