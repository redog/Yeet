1. **Modify `yeet.sh` to remove passwords and ensure format**:
   - In the `copy_key` function, check if the key is private (we can just run ssh-keygen on it if it's a private key).
   - If `$key_file` is a private key file, copy it to a temporary file, run `ssh-keygen -p -f "$temp_key" -N ""` on it.
   - Wait, `copy_key` supports passing a public key. If a public key is passed, it looks for the private key.
   - If a private key is found, copy it to a temporary file. Run `chmod 600` on the temporary file to avoid ssh-keygen complaining.
   - Run `ssh-keygen -p -f "$temp_key" -N ""`. If it fails (e.g. user aborts password prompt or invalid key), exit with an error.
   - Read the stripped private key from `$temp_key` and remove the temporary file.

2. **Modify `Yeet.ps1` to remove passwords and ensure format**:
   - In `Upload-BwSshKey`, similarly, if a private key is found, save a copy of it to a temporary location using `New-TemporaryFile`.
   - Call `Set-PrivateKeyPermissions` on the temporary file to ensure `ssh-keygen` doesn't complain about permissions on Windows.
   - Run `ssh-keygen -p -f "$tempKeyPath" -N '""'`.
   - If `$LASTEXITCODE -ne 0`, show an error and exit.
   - Read the normalized private key from `$tempKeyPath` and remove the temporary file.
   - Continue uploading with the stripped private key.

3. Complete pre commit steps to make sure proper testing, verifications, reviews and reflections are done.
4. Submit the change.
