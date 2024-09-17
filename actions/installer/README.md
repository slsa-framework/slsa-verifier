# Install slsa-verifier [![verifier action](https://github.com/slsa-framework/slsa-verifier/actions/workflows/e2e.schedule.installer.yml/badge.svg)](https://github.com/slsa-framework/slsa-verifier/actions/workflows/e2e.schedule.installer.yml)

This action installs the SLSA verifier and adds it to your `PATH` so it is
available in subsequent steps. To ensure integrity of the installed
`slsa-verifier` binary, this Action will [bootstrap](#bootstrapping) a known,
good, and stable version of the `slsa-verifier` and use it to attest and
validate the version being installed.

For more information about `slsa-verifier`, refer to
[its documentation](https://github.com/slsa-framework/slsa-verifier#verification-of-provenance).

For available SLSA verifier releases, refer to
[its releases](https://github.com/slsa-framework/slsa-verifier/releases).

For more information about SLSA in general, see
[https://slsa.dev](https://slsa.dev).

> This action supports Linux, macOS and Windows runners (results may vary with
> self-hosted runners).

## Quick Start

```yaml
- name: Install slsa-verifier
  uses: slsa-framework/slsa-verifier/actions/installer@v2.6.0
```

## Usage

> [!NOTE]
>
> If the version being installed matches the [bootstrap](#bootstrapping) version
> then this Action will install the bootstrap `slsa-verifier` after verification
> and consider it a `cache-hit`.

### Inputs

| Name      | Type    | Description                                              | Default                    |
| --------- | ------- | -------------------------------------------------------- | -------------------------- |
| `version` | String  | `slsa-verifier` version to be installed                  | `${{ github.action_ref }}` |
| `cache`   | Boolean | Whether to utilize cache with the `slsa-verifier` binary | `true`                     |
| `token`   | String  | GitHub Token for REST API access                         | `${{ github.token }}`      |

### Outputs

| Name        | Type    | Description                                       |
| ----------- | ------- | ------------------------------------------------- |
| `version`   | String  | The version of `slsa-verifier` that was installed |
| `cache-hit` | Boolean | If `slsa-verifier` was installed via cache        |

## Bootstrapping

The following bootstrap `slsa-verifier` version information is
[hardcoded](src/bootstrap.ts) into this Action.

| Version  | OS        | Arch    | SHA                                                                |
| -------- | --------- | ------- | ------------------------------------------------------------------ |
| `v2.6.0` | `Darwin`  | `amd64` | `f838adf01bbe62b883e7967167fa827bbf7373f83e2d7727ec18e53f725fee93` |
| `v2.6.0` | `Darwin`  | `arm64` | `8740e66832fd48bbaa479acd5310986b876ff545460add0cb4a087aec056189c` |
| `v2.6.0` | `Linux`   | `amd64` | `1c9c0d6a272063f3def6d233fa3372adbaff1f5a3480611a07c744e73246b62d` |
| `v2.6.0` | `Linux`   | `arm64` | `92b28eb2db998f9a6a048336928b29a38cb100076cd587e443ca0a2543d7c93d` |
| `v2.6.0` | `Windows` | `amd64` | `37ca29ad748e8ea7be76d3ae766e8fa505362240431f6ea7f0648c727e2f2507` |
| `v2.6.0` | `Windows` | `arm64` | `6235daec8037a2e8f6aa11c583eed6b09b2cd36b61b43b9e5898281b39416d2f` |

## Supported Versions

| Version    | Linux | macOS | Windows |
| ---------- | ----- | ----- | ------- |
| `>= 2.1.0` | ✅    | ✅    | ✅      |
| `< 2.1.0`  | ✅    | ❌    | ❌      |

macOS and Windows builds only started as of `v2.1.0`, so while you can use this
Action to installer older Linux builds, it won't work for Windows and macOS.

## Development

> [!WARNING]
>
> Since this is a TypeScript action you **must** transpile it into native
> JavaScript. This is done for you automatically as part of the `npm run all`
> command and will be validated during the
> [Installer Action CI](https://github.com/slsa-framework/slsa-verifier/actions/workflows/e2e.schedule.installer.yml)
> Workflow in any PR.

1. ⚙️ Install the version of [Node.js](https://nodejs.org/en) as defined in the
   [`.node-version`](.node-version) file.

2. 🛠️ Install dependencies

   ```sh
   npm install
   ```

3. 🏗️ Format, lint, test, and package your code changes.

   ```sh
   npm run all
   ```
