# Yeet

A set of scripts for managing SSH keys with Bitwarden.

## Installation

1. Install the Bitwarden CLI (`bw`).
2. Log in to Bitwarden and unlock your vault.

---

## Yeet.ps1 (PowerShell)

This script is intended for use in PowerShell environments (Windows).
Requires PowerShell 5.1 or newer.

### Usage

#### `list`

Lists all SSH keys stored in your Bitwarden vault.

```powershell
.\Yeet.ps1 list
```

#### `get <key-name>`

Retrieves the specified SSH key from Bitwarden and saves it to `~/.ssh/<key-name>`.
It also attempts to add the public key to `authorized_keys`.

```powershell
.\Yeet.ps1 get my-server-key
```

#### `create`

Creates a new SSH key (ED25519), saves it locally, and uploads it to Bitwarden.

```powershell
.\Yeet.ps1 create
```

#### `upload <source-key-path> <target-name>`

Uploads an existing local key to Bitwarden with a new name.

```powershell
.\Yeet.ps1 upload "C:\Users\Me\.ssh\id_rsa" "my-uploaded-key"
```
---

## yeet.sh (Bash)

This script is intended for use in Bash environments.

### Usage

#### `list`

Lists all SSH keys stored in your Bitwarden vault, including expiration status if available.

```bash
./yeet.sh list
```

#### `get <key-name>`

Retrieves the specified SSH key from Bitwarden and saves it to `~/.ssh/<key-name>`.

```bash
./yeet.sh get my-server-key
```

#### `create`

Creates a new SSH key, saves it to `~/.ssh/<hostname>-<date>`, and uploads it to Bitwarden.

```bash
./yeet.sh create
```

#### `upload <source-key-path> <new-key-name>`

Uploads an existing local key to Bitwarden with a new name.

```bash
./yeet.sh upload ~/.ssh/id_rsa my-personal-key
```

---
