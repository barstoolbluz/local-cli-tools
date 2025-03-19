# AWS CLI wrapper with just-in-time credential injection
function aws_secure
  # Get credentials just-in-time
  set -l aws_creds (get_from_keychain "aws" "$USER")

  # Parse JSON with fish's built-in string manipulation
  set -l aws_access_key_id (echo $aws_creds | string match -r '"aws_access_key_id":"([^"]*)"' | string replace -r '"aws_access_key_id":"([^"]*)"' '$1')
  set -l aws_secret_access_key (echo $aws_creds | string match -r '"aws_secret_access_key":"([^"]*)"' | string replace -r '"aws_secret_access_key":"([^"]*)"' '$1')

  if test -z "$aws_access_key_id" -o -z "$aws_secret_access_key"
    echo "No AWS credentials found in keychain. Run 'aws configure' first." >&2
    return 1
  end

  # Run command with credentials ONLY for this command
  env AWS_ACCESS_KEY_ID="$aws_access_key_id" \
      AWS_SECRET_ACCESS_KEY="$aws_secret_access_key" \
      aws $argv
end

# GitHub CLI wrapper with just-in-time token injection
function gh_secure
  # Get token just-in-time
  set -l token (get_from_keychain "github" "$USER")

  if test -z "$token"
    echo "No GitHub token found in keychain. Run 'gh auth login' first." >&2
    return 1
  end

  # Run command with temporary environment - ONLY for this command
  env GITHUB_TOKEN="$token" \
      GH_TOKEN="$token" \
      gh $argv
end

function git_secure
  # Check if we're in a GitHub repo
  if git remote -v 2>/dev/null | grep -q 'github.com'
    # Use GitHub token for GitHub repos
    set -l token (get_from_keychain "github" "$USER")
    if test -n "$token"
      env GIT_ASKPASS="echo" \
          GIT_USERNAME="token" \
          GIT_PASSWORD="$token" \
          git $argv
      return $status
    end
  end

  # For non-GitHub repos or if no token found, fall back to normal git
  git $argv
end

# Helper function to access keychain/keyring (simplified version)
function get_from_keychain
  set -l service $argv[1]
  set -l username $argv[2]
  
  # Determine platform and use appropriate keychain method
  switch (uname)
    case Darwin
      # macOS - use Keychain
      security find-generic-password -s "${service}_flox" -a "$username" -w 2>/dev/null
    case '*'
      # Linux - use libsecret if available
      if type -q secret-tool
        secret-tool lookup service "${service}_cli" username "$username" 2>/dev/null
      else
        # Fallback to file-based storage
        set -l cred_file "$FLOX_ENV_CACHE/${service}_credential"
        if test -f "$cred_file"
          openssl enc -aes-256-cbc -d -salt -pbkdf2 -in "$cred_file" -k "flox-${service}-${USER}" 2>/dev/null
        end
      end
  end
end
