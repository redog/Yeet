#!/bin/bash

bw_is_logged_in() {
  bw status | grep -q '"status":"unlocked"'
}

list_keys() {
    if ! bw_is_logged_in; then
        echo "Error: Bitwarden is not logged in."
        return 1
    fi

    echo "Available SSH Keys in Bitwarden:"
    echo "--------------------------------"
    bw list items | jq -r '
        .[] | # Iterate over each item in the array
        select(.type == 5) | . as $item | # Filter for SSH keys and save the item

        # First, check if the .expires field is a string, THEN check if it is non-empty.
        # This prevents passing `null` to the `test` function.
        if ($item.sshKey.metadata.expires | type == "string" and test(".+")) then
            # Calculate days remaining and store in a variable
            ((($item.sshKey.metadata.expires | fromdate) - now) / 86400 | floor) as $days_left |
            
            # Now, use the variable in a new set of conditions
            if $days_left < 0 then
                "\($item.name) (EXPIRED \(-$days_left) days ago)"
            elif $days_left == 0 then
                "\($item.name) (Expires TODAY)"
            else
                "\($item.name) (Expires in \($days_left) days)"
            end
        else
            # If no expiration date is set (field is null, not a string, or an empty string)
            "\($item.name) (No expiration)"
        end
    '
}

check_key_expiration() {
    local key_json="$1"
    local expiration=$(echo "$key_json" | jq -r '.sshKey.metadata.expires')

    if [ ! -z "$expiration" ] && [ "$expiration" != "null" ]; then
        local today=$(date -I)
        local days_until_expiration=$(( ( $(date -d "$expiration" +%s) - $(date -d "$today" +%s) ) / 86400 ))

        if [ $days_until_expiration -lt 0 ]; then
            echo "Warning: This key has expired ($days_until_expiration days ago)"
            return 1
        elif [ $days_until_expiration -eq 0 ]; then
            echo "Warning: This key expires today!"
            return 1
        elif [ $days_until_expiration -le 30 ]; then
            echo "Warning: This key will expire in $days_until_expiration days"
        fi
    fi
    return 0
}

get_expiration_input() {
    while true; do
        echo "Set key expiration:"
        echo "1) 365 days (default)"
        echo "2) Custom days"
        echo "3) Never expire"
        read -r -p "Choose option [1-3]: " exp_choice

        case "$exp_choice" in
            ""|"1")
                echo "$(date -d "+365 days" -I)"
                return
                ;;
            "2")
                while true; do
                    read -r -p "Enter number of days (1-3650): " days
                    if [[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] && [ "$days" -le 3650 ]; then
                        echo "$(date -d "+$days days" -I)"
                        return
                    else
                        echo "Please enter a valid number between 1 and 3650"
                    fi
                done
                ;;
            "3")
                echo ""
                return
                ;;
            *)
                echo "Invalid option, please try again"
                ;;
        esac
    done
}

get_key() {
    if ! bw_is_logged_in; then
        echo "Error: Bitwarden is not logged in."
        exit 1
    fi
    local key_name="$1"
    if [ -z "$key_name" ]; then
        echo "Usage: $0 get <key_name>"
        exit 1
    fi
    local item_id=$(bw list items | jq -r --arg key_name "$key_name" '.[] | select(.type == 5 and .name == $key_name) | .id')

    if [ -z "$item_id" ]; then
        echo "Error: Could not find a key named '$key_name'."
        exit 1
    fi

    local item_json=$(bw get item "$item_id")

    local private_key=$(echo "$item_json" | jq -r '.sshKey.privateKey')
    local public_key=$(echo "$item_json" | jq -r '.sshKey.publicKey')

    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        echo "Error: Could not retrieve the private or public key from Bitwarden."
        exit 1
    fi

    local key_path="$HOME/.ssh/$key_name"
    echo "$private_key" > "$key_path"
    chmod 600 "$key_path"
    echo "Private key '$key_name' saved to '$key_path'"
    read -r -p "Encrypt the private key with a passphrase? (y/n): " encrypt_confirm
    if [[ "$encrypt_confirm" =~ ^[Yy]$ ]]; then
        ssh-keygen -p -f "$key_path"
        if [ $? -eq 0 ]; then
            echo "Private key encrypted with passphrase."
        else
            echo "Warning: Failed to encrypt private key."
        fi
    fi
    read -r -p "Add public key to ~/.ssh/authorized_keys? (y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo "$public_key" >> "$HOME/.ssh/authorized_keys"
        chmod 600 "$HOME/.ssh/authorized_keys"
        echo "Public key added to ~/.ssh/authorized_keys"
    else
        echo "Public key not added to ~/.ssh/authorized_keys"
    fi
}

create_key() {
  if ! bw_is_logged_in; then
    echo "Error: Bitwarden is not logged in."
    exit 1
  fi

  local default_key_name=$(hostname -s)-$(date +%Y-%m)
  read -r -p "Enter a name for the new SSH key (default: $default_key_name): " key_name
  key_name="${key_name:-$default_key_name}"

  if [ -z "$key_name" ]; then
    echo "Error: Key name cannot be empty."
    exit 1
  fi

  local key_path="$HOME/.ssh/$key_name"
  if [ -f "$key_path" ]; then
      echo "Error: A key file already exists at '$key_path'."
      exit 1
  fi
  ssh-keygen -t ed25519 -f "$key_path" -N ""

  if [ $? -ne 0 ]; then
    echo "Error: SSH key generation failed."
    exit 1
  fi

  local private_key=$(cat "$key_path") 
  local public_key=$(cat "$key_path.pub")

  local key_fingerprint=$(ssh-keygen -lf "$key_path" | awk '{print $2}')

  bw get template item | \
    jq --arg name "$key_name" --arg privateKey "$private_key" --arg publicKey "$public_key" --arg keyFingerprint "$key_fingerprint" '. + {type: 5, name: $name, sshKey: {privateKey: $privateKey, publicKey: $publicKey, keyFingerprint: $keyFingerprint}}' | \
    bw encode | \
    bw create item > /dev/null 2>&1

  if [ $? -ne 0 ]; then
    echo "Error: Failed to save the key to Bitwarden. The local key has been created."
    exit 1
  fi

  chmod 600 "$key_path"
  echo "SSH key '$key_name' created and saved to '$key_path' and Bitwarden."
  read -r -p "Encrypt the local private key with a passphrase? (y/n): " encrypt_confirm
  if [[ "$encrypt_confirm" =~ ^[Yy]$ ]]; then
      ssh-keygen -p -f "$key_path"
      if [ $? -eq 0 ]; then
          echo "Private key encrypted with passphrase."
      else
          echo "Warning: Failed to encrypt private key."
      fi
  fi

  read -r -p "Add public key to ~/.ssh/authorized_keys? (y/n): " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
      echo "$public_key" >> "$HOME/.ssh/authorized_keys"
      chmod 600 "$HOME/.ssh/authorized_keys"
      echo "Public key added to ~/.ssh/authorized_keys"
  else
      echo "Public key not added to ~/.ssh/authorized_keys"
  fi
}

copy_key() {
  if ! bw_is_logged_in; then
    echo "Error: Bitwarden is not logged in."
    exit 1
  fi

  local src_path="$1"
  local new_name="$2"

  if [ -z "$src_path" ] || [ -z "$new_name" ]; then
    echo "Usage: $0 upload <source_key_path> <new_key_name>"
    exit 1
  fi

  if [ ! -f "$src_path" ]; then
    echo "Error: Source key '$src_path' not found."
    exit 1
  fi

  local key_file="$src_path"
  local private_key=""
  local public_key=""

  if [[ "$src_path" == *.pub ]]; then
    public_key=$(cat "$src_path")
    key_file="${src_path%.pub}"
  fi

  if [ -f "$key_file" ]; then
    # Create a temporary file to process the private key
    local temp_key=$(mktemp)
    cp "$key_file" "$temp_key"
    chmod 600 "$temp_key"

    # Strip password and convert to PKCS8 format
    ssh-keygen -p -m PKCS8 -f "$temp_key" -N "" > /dev/null
    if [ $? -ne 0 ]; then
      echo "Error: Failed to process private key. Ensure you have the correct passphrase if it is encrypted."
      rm -f "$temp_key"
      exit 1
    fi

    private_key=$(cat "$temp_key")
    rm -f "$temp_key"
  fi

  if [ -z "$public_key" ] && [ -f "${key_file}.pub" ]; then
    public_key=$(cat "${key_file}.pub")
  fi

  if [ -z "$public_key" ] && [ -n "$private_key" ]; then
    # We use ssh-keygen on the processed private key, which requires a file.
    local temp_pub_src=$(mktemp)
    echo "$private_key" > "$temp_pub_src"
    chmod 600 "$temp_pub_src"
    public_key=$(ssh-keygen -y -f "$temp_pub_src")
    rm -f "$temp_pub_src"
  fi

  # Normalize line endings: remove \r and trim trailing blank lines, ensuring exactly one trailing \n
  if [ -n "$private_key" ]; then
    private_key=$(printf "%s" "$private_key" | tr -d '\r')
    private_key="${private_key}"$'\n'
  fi

  if [ -n "$public_key" ]; then
    public_key=$(printf "%s" "$public_key" | tr -d '\r')
    public_key="${public_key}"$'\n'
  fi

  local fingerprint_source="$src_path"
  [ -f "$key_file" ] && fingerprint_source="$key_file"
  local key_fingerprint=$(ssh-keygen -lf "$fingerprint_source" | awk '{print $2}')

  local existing=$(bw list items | jq -r --arg n "$new_name" '.[] | select(.type == 5 and .name == $n) | .id')
  if [ -n "$existing" ]; then
    echo "Error: A key named '$new_name' already exists in Bitwarden."
    exit 1
  fi

  bw get template item | \
    jq --arg name "$new_name" --arg privateKey "$private_key" --arg publicKey "$public_key" --arg keyFingerprint "$key_fingerprint" '. + {type: 5, name: $name, sshKey: {privateKey: $privateKey, publicKey: $publicKey, keyFingerprint: $keyFingerprint}}' | \
    bw encode | bw create item > /dev/null 2>&1

  if [ $? -ne 0 ]; then
    echo "Error: Failed to save the key to Bitwarden."
    exit 1
  fi
  echo "SSH key '$src_path' uploaded to Bitwarden as '$new_name'."
}

if ! command -v bw &> /dev/null; then
  echo "Error: Bitwarden CLI (bw) is not installed."
  exit 1
fi

if [ -z "$1" ]; then
    echo "Usage:"
    echo "  $0 list      - List available SSH keys"
    echo "  $0 get <keyname> - Get a key and add pub key to authorized_keys"
    echo "  $0 create    - Creates and upload a key"
    echo "  $0 upload <source> <new> - Copy a local key to a new name and upload"
    exit 0
fi

case "$1" in
  list)
    list_keys
    ;;
  get)
    get_key "$2"
    ;;
  create)
    create_key
    ;;
  upload)
    copy_key "$2" "$3"
    ;;
  *)
    echo "Invalid command: $1"
    exit 1
    ;;
esac

exit 0
