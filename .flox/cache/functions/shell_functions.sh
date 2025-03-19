# AWS CLI wrapper with just-in-time credential injection
aws_secure() {
  # Get credentials just-in-time
  local aws_creds=$(get_from_keychain "aws" "$USER")
  local aws_access_key_id=$(echo "$aws_creds" | jq -r '.aws_access_key_id' 2>/dev/null || echo "")
  local aws_secret_access_key=$(echo "$aws_creds" | jq -r '.aws_secret_access_key' 2>/dev/null || echo "")
  
  if [[ -z "$aws_access_key_id" || -z "$aws_secret_access_key" ]]; then
    echo "No AWS credentials found in keychain. Run 'aws configure' first." >&2
    return 1
  fi
  
  # Run command with credentials ONLY for this command
  # This does NOT export to the environment, only to this command
  AWS_ACCESS_KEY_ID="$aws_access_key_id" \
  AWS_SECRET_ACCESS_KEY="$aws_secret_access_key" \
  aws "$@"
}

# GitHub CLI wrapper with just-in-time token injection
gh_secure() {
  # Check if GitHub CLI is already authenticated
  if gh auth status &>/dev/null; then
    # Use the already authenticated GitHub CLI
    gh "$@"
  else
    echo "GitHub CLI not authenticated. Run 'gh auth login' first." >&2
    return 1
  fi
}

# Git wrapper for non-GitHub repositories
git_secure() {
  # Check if we're in a GitHub repo or accessing GitHub
  if git remote -v 2>/dev/null | grep -q 'github.com' || [[ "$*" == *"github.com"* ]]; then
    # Get token directly from GitHub CLI
    if command -v gh &>/dev/null && gh auth status &>/dev/null 2>&1; then
      local token=$(gh auth token 2>/dev/null)
      if [[ -n "$token" ]]; then
        # Create a temporary script to serve as GIT_ASKPASS
        local tmp_askpass=$(mktemp)
        echo '#!/bin/sh' > "$tmp_askpass"
        echo 'echo "'$token'"' >> "$tmp_askpass"
        chmod +x "$tmp_askpass"
        
        # Use the script to provide credentials
        GIT_ASKPASS="$tmp_askpass" \
        git "$@"
        
        # Remove the temporary script
        rm -f "$tmp_askpass"
        return $?
      fi
    fi
  fi
  
  # Fall back to normal git
  git "$@"
}

# Helper function to access keychain/keyring (simplified version)
get_from_keychain() {
  local service="$1"
  local username="$2"
  
  # Determine platform and use appropriate keychain method
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use Keychain
    security find-generic-password -s "${service}_flox" -a "$username" -w 2>/dev/null
  else
    # Linux - use libsecret if available
    if command -v secret-tool &> /dev/null; then
      secret-tool lookup service "${service}_cli" username "$username" 2>/dev/null
    else
      # Fallback to file-based storage
      local cred_file="${FLOX_ENV_CACHE}/${service}_credential"
      if [[ -f "$cred_file" ]]; then
        openssl enc -aes-256-cbc -d -salt -pbkdf2 -in "$cred_file" -k "flox-${service}-${USER}" 2>/dev/null
      fi
    fi
  fi
}
