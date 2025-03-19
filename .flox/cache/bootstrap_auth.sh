#!/usr/bin/env bash
# Authentication Management for GitHub, Git, and AWS in Flox Environment

# --------------------------------
# Common Utility Functions
# --------------------------------

# Function to determine if system keychain is available
has_system_keychain() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    command -v security &> /dev/null
    return $?
  else
    command -v secret-tool &> /dev/null
    return $?
  fi
}

# Function to securely store credentials in system keychain
store_in_keychain() {
  local service="$1"
  local username="$2"
  local credential="$3"
  
  # Trim whitespace and newlines for safety
  credential=$(echo -n "$credential" | tr -d '[:space:]')
  
  # Determine platform and use appropriate keychain method
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use Keychain
    security add-generic-password -s "${service}_flox" -a "$username" -w "$credential" -U
    return $?
  else
    # Linux - use libsecret if available
    if command -v secret-tool &> /dev/null; then
      echo -n "$credential" | secret-tool store --label="${service} CLI Flox" service "${service}_cli" username "$username"
      return $?
    fi
    return 1
  fi
}

# Function to retrieve credentials from system keychain
get_from_keychain() {
  local service="$1"
  local username="$2"
  
  # Determine platform and use appropriate keychain method
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use Keychain
    security find-generic-password -s "${service}_flox" -a "$username" -w 2>/dev/null
    return $?
  else
    # Linux - use libsecret if available
    if command -v secret-tool &> /dev/null; then
      secret-tool lookup service "${service}_cli" username "$username" 2>/dev/null
      return $?
    fi
    return 1
  fi
}

# Function to store credentials in file (fallback)
store_in_file() {
  local service="$1"
  local credential="$2"
  local cred_file="${FLOX_ENV_CACHE}/${service}_credential"
  
  # Ensure directory exists
  mkdir -p "${FLOX_ENV_CACHE}"
  
  # Store encrypted credential (using openssl for simple encryption)
  echo "$credential" | openssl enc -aes-256-cbc -salt -pbkdf2 -out "$cred_file" -k "flox-${service}-${USER}"
  
  # Set restrictive permissions
  chmod 600 "$cred_file"
  return $?
}

# Function to retrieve credentials from file (fallback)
get_from_file() {
  local service="$1"
  local cred_file="${FLOX_ENV_CACHE}/${service}_credential"
  
  # Check if credential file exists
  if [[ -f "$cred_file" ]]; then
    # Decrypt and return credential
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -in "$cred_file" -k "flox-${service}-${USER}" 2>/dev/null
    return $?
  fi
  return 1
}

# Function to prompt for credentials
prompt_for_credential() {
  local service="$1"
  local prompt_text="$2"
  
  gum style --foreground 212 "$service authentication required for this environment"
  gum style --foreground 212 "$prompt_text"
  local credential=$(gum input --password --placeholder "Enter credential" --value "")
  
  # Trim whitespace and newlines
  credential=$(echo -n "$credential" | tr -d '[:space:]')
  
  if [[ -n "$credential" ]]; then
    echo "$credential"
    return 0
  else
    return 1
  fi
}

# Function to handle storage of credentials based on available methods
store_credential() {
  local service="$1"
  local username="$2"
  local credential="$3"
  
  # Try to store in system keychain first
  if has_system_keychain; then
    if store_in_keychain "$service" "$username" "$credential"; then
      gum style --foreground 114 "✓ $service credential stored in system keychain"
      return 0
    fi
  fi
  
  # Fallback to file-based storage with user consent
  gum style --foreground 214 "No system keychain available for secure storage."
  gum style --foreground 214 "Would you like to store your $service credential in an encrypted file?"
  gum style --foreground 214 "(Less secure than system keychain, but better than plain text)"
  
  if gum confirm "Store credential in encrypted file?"; then
    if store_in_file "$service" "$credential"; then
      gum style --foreground 114 "✓ $service credential stored in encrypted file"
      return 0
    else
      gum style --foreground 160 "✗ Failed to store $service credential in encrypted file"
    fi
  else
    gum style --foreground 212 "Credential will not be stored persistently on disk."
    gum style --foreground 212 "Using as environment variable for this session only."
  fi
  
  return 1
}

# Function to retrieve credential using all available methods
get_credential() {
  local service="$1"
  local username="$2"
  local credential=""
  
  # Try system keychain first
  if has_system_keychain; then
    credential=$(get_from_keychain "$service" "$username")
    if [[ -n "$credential" ]]; then
      echo "$credential"
      return 0
    fi
  fi
  
  # Try file-based storage next
  credential=$(get_from_file "$service")
  if [[ -n "$credential" ]]; then
    echo "$credential"
    return 0
  fi
  
  return 1
}

# --------------------------------
# GitHub Authentication
# --------------------------------

# Function to check if gh is authenticated
check_gh_auth() {
  # Try to get the current auth status
  if gh auth status &> /dev/null; then
    return 0
  else
    return 1
  fi
}

# Function to authenticate gh cli with token
authenticate_gh() {
  local token="$1"
  
  if [[ -n "$token" ]]; then
    # Write token to a temporary file to avoid issues with echo/pipe
    local tmp_token_file=$(mktemp)
    echo -n "$token" > "$tmp_token_file"
    
    # Use the file directly with gh auth
    gh auth login --with-token < "$tmp_token_file"
    local auth_status=$?
    
    # Securely remove the temporary file
    rm -f "$tmp_token_file"
    
    if [[ $auth_status -eq 0 ]]; then
      # If authentication was successful, also set environment variables
      export GITHUB_TOKEN="$token"
      export GH_TOKEN="$token"
      
      # Don't configure Git to use the GitHub CLI helper - will use secure wrapper functions instead
      gum style --foreground 114 "✓ GitHub authentication successful"
    fi
    
    return $auth_status
  else
    return 1
  fi
}

# Main function to bootstrap GitHub authentication
bootstrap_github_auth() {
  # Check if already authenticated
  if check_gh_auth; then
    gum style --foreground 114 "✓ GitHub authentication already configured"
    return 0
  fi
  
  # Try to get token from keychain or file
  local token=$(get_credential "github" "$USER")
  
  # If no stored token, prompt for one
  if [[ -z "$token" ]]; then
    token=$(prompt_for_credential "GitHub" "Please paste your GitHub personal access token:")
    if [[ -z "$token" ]]; then
      gum style --foreground 160 "✗ No token provided"
      gum style --foreground 212 "You can authenticate manually by running 'gh auth login' after activation"
      return 1
    fi
  fi
  
  # Set environment variables for this session
  export GITHUB_TOKEN="$token"
  export GH_TOKEN="$token"
  
  # Try to authenticate
  gum style --foreground 212 "Attempting GitHub authentication..."
  
  # First try with environment variables
  if gh api user &>/dev/null; then
    # Authentication worked - do not set up git credential helper
    # Will use secure wrapper functions instead
    
    # Store the token if not already stored
    store_credential "github" "$USER" "$token"
    
    gum style --foreground 114 "✓ GitHub authentication successful"
    return 0
  else
    # Try with gh auth login as fallback
    gum style --foreground 212 "Trying alternative authentication method..."
    if authenticate_gh "$token"; then
      # Store the token if authentication was successful
      store_credential "github" "$USER" "$token"
      
      gum style --foreground 114 "✓ GitHub authentication successful with alternative method"
      return 0
    else
      gum style --foreground 160 "✗ Authentication failed"
      gum style --foreground 212 "You can authenticate manually by running 'gh auth login' after activation"
      return 1
    fi
  fi
}

# --------------------------------
# AWS Authentication
# --------------------------------

# Function to check if AWS credentials are configured
check_aws_auth() {
  if command -v aws &> /dev/null; then
    # Check if AWS credentials are configured
    if aws sts get-caller-identity &> /dev/null; then
      return 0
    fi
  fi
  return 1
}

# Function to set AWS credentials in environment and config
configure_aws_credentials() {
  local aws_access_key_id="$1"
  local aws_secret_access_key="$2"
  
  # Test the credentials without persisting them anywhere
  # Create a temporary environment just for this check and then discard it
  AWS_ACCESS_KEY_ID="$aws_access_key_id" \
  AWS_SECRET_ACCESS_KEY="$aws_secret_access_key" \
  aws sts get-caller-identity &>/dev/null
  
  return $?
}

# Main function to bootstrap AWS authentication
bootstrap_aws_auth() {
  # Check if AWS CLI is installed
  if ! command -v aws &> /dev/null; then
    gum style --foreground 214 "AWS CLI not found, skipping AWS authentication"
    return 0
  fi
  
  # Check if already authenticated
  if check_aws_auth; then
    gum style --foreground 114 "✓ AWS authentication already configured"
    return 0
  fi
  
  # Try to get credentials from keychain or file (stored as JSON)
  local aws_creds=$(get_credential "aws" "$USER")
  local aws_access_key_id=""
  local aws_secret_access_key=""
  
  if [[ -n "$aws_creds" ]]; then
    # Parse JSON-formatted credentials
    if command -v jq &> /dev/null; then
      aws_access_key_id=$(echo "$aws_creds" | jq -r '.aws_access_key_id')
      aws_secret_access_key=$(echo "$aws_creds" | jq -r '.aws_secret_access_key')
    else
      # Simple fallback parsing for environments without jq
      aws_access_key_id=$(echo "$aws_creds" | grep -o '"aws_access_key_id":"[^"]*"' | cut -d'"' -f4)
      aws_secret_access_key=$(echo "$aws_creds" | grep -o '"aws_secret_access_key":"[^"]*"' | cut -d'"' -f4)
    fi
  fi
  
  # If no stored credentials, prompt for them
  if [[ -z "$aws_access_key_id" || -z "$aws_secret_access_key" ]]; then
    gum style --foreground 212 "Please enter your AWS credentials:"
    aws_access_key_id=$(gum input --placeholder "AWS Access Key ID" --value "")
    aws_secret_access_key=$(gum input --password --placeholder "AWS Secret Access Key" --value "")
    
    if [[ -z "$aws_access_key_id" || -z "$aws_secret_access_key" ]]; then
      gum style --foreground 160 "✗ Incomplete AWS credentials provided"
      gum style --foreground 212 "You can configure AWS manually by running 'aws configure' after activation"
      return 1
    fi
  fi
  
  # Configure AWS with the credentials
  if configure_aws_credentials "$aws_access_key_id" "$aws_secret_access_key"; then
    # Store credentials in JSON format
    local aws_creds_json="{\"aws_access_key_id\":\"$aws_access_key_id\",\"aws_secret_access_key\":\"$aws_secret_access_key\"}"
    store_credential "aws" "$USER" "$aws_creds_json"
    
    gum style --foreground 114 "✓ AWS authentication successful"
    return 0
  else
    gum style --foreground 160 "✗ AWS configuration failed"
    gum style --foreground 212 "You can configure AWS manually by running 'aws configure' after activation"
    return 1
  fi
}

# --------------------------------
# Git Authentication (non-GitHub)
# --------------------------------

# Function to configure Git credentials without GitHub
configure_git_credentials() {
  # Check if Git's credential.helper is already configured
  local current_helper=$(git config --global --get credential.helper)
  
  # Skip if some helper is already set
  if [[ -n "$current_helper" ]]; then
    # But ensure it's not the problematic 'gh auth git-credential'
    if [[ "$current_helper" == "gh auth git-credential" ]]; then
      gum style --foreground 214 "! Removing problematic git credential helper"
      git config --global --unset credential.helper
    else
      gum style --foreground 114 "✓ Git credential helper already configured: $current_helper"
      return 0
    fi
  fi
  
  # Set up Git credential storage based on platform
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use osxkeychain
    git config --global credential.helper osxkeychain
    gum style --foreground 114 "✓ Git configured to use macOS Keychain"
    return 0
  elif [[ "$OSTYPE" == "linux"* ]]; then
    # Linux - use libsecret if available
    if command -v git-credential-libsecret &> /dev/null; then
      git config --global credential.helper libsecret
      gum style --foreground 114 "✓ Git configured to use libsecret"
      return 0
    # Otherwise use cache with a reasonable timeout
    else
      git config --global credential.helper 'cache --timeout=86400'
      gum style --foreground 214 "! Git configured to use in-memory cache (24-hour timeout)"
      gum style --foreground 214 "  Consider installing libsecret for more secure credential storage"
      return 0
    fi
  fi
  
  gum style --foreground 214 "! No suitable credential helper found, using wrapper functions only"
  return 0
}

# Main function to bootstrap Git authentication
bootstrap_git_auth() {
  # Only configure Git authentication if GitHub auth failed or wasn't attempted
  if ! check_gh_auth; then
    gum style --foreground 212 "Configuring Git credential storage..."
    configure_git_credentials
  fi
}

# --------------------------------
# Shell Function Generation
# --------------------------------

# Function to generate shell wrapper functions
generate_shell_functions() {
  # Create directory for shell function files
  mkdir -p "${FLOX_ENV_CACHE}/functions"

  # ------------------------------------
  # Bash/Zsh Functions (mostly compatible)
  # ------------------------------------
  cat > "${FLOX_ENV_CACHE}/functions/shell_functions.sh" << 'EOF'
# AWS CLI wrapper with just-in-time credential injection
aws() {
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
  command aws "$@"
}

# Git wrapper for non-GitHub repositories
git() {
  # Debug function for troubleshooting
  debug_git() {
    [[ -n "$FLOX_DEBUG" ]] && echo "[DEBUG] $*" >&2
  }
  
  # For clone operations, directly handle GitHub URLs
  if [[ "$1" == "clone" && "$2" == *"github.com"* ]]; then
    debug_git "GitHub clone detected"
    
    # Try to get token from GitHub CLI first (most reliable)
    local token=""
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
      token=$(gh auth token 2>/dev/null)
      debug_git "Got token from GitHub CLI"
    fi
    
    # Fallback to our keychain if gh auth token failed
    if [[ -z "$token" ]]; then
      token=$(get_credential "github" "$USER" 2>/dev/null)
      debug_git "Used keychain token"
    fi
    
    if [[ -n "$token" ]]; then
      debug_git "Using token for authentication"
      
      # Create modified URL with token embedded
      local orig_url="$2"
      local auth_url="https://oauth2:${token}@${orig_url#https://}"
      
      debug_git "Original URL: $orig_url"
      debug_git "Auth URL format: https://oauth2:***@${orig_url#https://}"
      
      # Use printf to avoid issues with special characters in the token
      printf -v cmd_str "%s %s %s" "command git clone" "$auth_url" "${*:3}"
      eval "$cmd_str"
      return $?
    else
      debug_git "No token found, proceeding with regular git"
    fi
  # For other GitHub operations
  elif command git rev-parse --is-inside-work-tree &>/dev/null 2>&1; then
    if command git remote -v 2>/dev/null | grep -q 'github.com'; then
      debug_git "GitHub repository operation detected"
      
      # Try to get token from GitHub CLI first
      local token=""
      if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        token=$(gh auth token 2>/dev/null)
      fi
      
      # Fallback to our keychain
      if [[ -z "$token" ]]; then
        token=$(get_credential "github" "$USER" 2>/dev/null)
      fi
      
      if [[ -n "$token" ]]; then
        debug_git "Using token for GitHub operation"
        
        # Create a temporary script that outputs the password
        local askpass_script=$(mktemp)
        echo '#!/bin/sh
echo "$GIT_PASSWORD"' > "$askpass_script"
        chmod +x "$askpass_script"
        
        # Run git with properly configured environment
        GIT_ASKPASS="$askpass_script" \
        GIT_USERNAME="oauth2" \
        GIT_PASSWORD="$token" \
        command git "$@"
        
        local ret=$?
        
        # Clean up
        rm -f "$askpass_script"
        return $ret
      fi
    fi
  fi
  
  # Default case: run git normally
  debug_git "Using standard git command"
  command git "$@"
}

# Helper function to access keychain/keyring
get_from_keychain() {
  local service="$1"
  local username="$2"
  
  # If GitHub is the service and gh CLI is available, try that first
  if [[ "$service" == "github" ]] && command -v gh &>/dev/null; then
    if gh auth status &>/dev/null; then
      gh auth token 2>/dev/null
      local gh_status=$?
      if [[ $gh_status -eq 0 ]]; then
        return 0
      fi
    fi
  fi
  
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
EOF

  # ------------------------------------
  # Fish Functions
  # ------------------------------------
  cat > "${FLOX_ENV_CACHE}/functions/shell_functions.fish" << 'EOF'
# AWS CLI wrapper with just-in-time credential injection
function aws
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
      command aws $argv
end

function git
  # Debug function for troubleshooting
  function debug_git
    if set -q FLOX_DEBUG
      echo "[DEBUG] $argv" >&2
    end
  end
  
  # For clone operations, directly handle GitHub URLs
  if test "$argv[1]" = "clone"; and string match -q "*github.com*" "$argv[2]"
    debug_git "GitHub clone detected"
    
    # Try to get token from GitHub CLI first (most reliable)
    set -l token ""
    if type -q gh; and gh auth status &>/dev/null
      set token (gh auth token 2>/dev/null)
      debug_git "Got token from GitHub CLI"
    end
    
    # Fallback to our keychain if gh auth token failed
    if test -z "$token"
      set token (get_credential "github" "$USER" 2>/dev/null)
      debug_git "Used keychain token"
    end
    
    if test -n "$token"
      debug_git "Using token for authentication"
      
      # Create modified URL with token embedded
      set -l orig_url "$argv[2]"
      set -l auth_url "https://oauth2:$token@"(string replace "https://" "" "$orig_url")
      
      debug_git "Original URL: $orig_url"
      debug_git "Auth URL format: https://oauth2:***@"(string replace "https://" "" "$orig_url")
      
      # Build new command arguments
      set -l new_argv $argv[1] "$auth_url"
      if test (count $argv) -gt 2
        set -a new_argv $argv[3..-1]
      end
      
      debug_git "Running: git clone [AUTH_URL] $argv[3..-1]"
      command git $new_argv
      return $status
    else
      debug_git "No token found, proceeding with regular git"
    end
  # For other GitHub operations
  else if command git rev-parse --is-inside-work-tree &>/dev/null 2>&1
    if command git remote -v 2>/dev/null | grep -q 'github.com'
      debug_git "GitHub repository operation detected"
      
      # Try to get token from GitHub CLI first
      set -l token ""
      if type -q gh; and gh auth status &>/dev/null
        set token (gh auth token 2>/dev/null)
      end
      
      # Fallback to our keychain
      if test -z "$token"
        set token (get_credential "github" "$USER" 2>/dev/null)
      end
      
      if test -n "$token"
        debug_git "Using token for GitHub operation"
        
        # Create a temporary script that outputs the password
        set -l askpass_script (mktemp)
        echo '#!/bin/sh
echo "$GIT_PASSWORD"' > "$askpass_script"
        chmod +x "$askpass_script"
        
        # Run git with properly configured environment
        env GIT_ASKPASS="$askpass_script" \
            GIT_USERNAME="oauth2" \
            GIT_PASSWORD="$token" \
            command git $argv
        
        set -l ret $status
        
        # Clean up
        rm -f "$askpass_script"
        return $ret
      end
    end
  end
  
  # Default case: run git normally
  debug_git "Using standard git command"
  command git $argv
end

# Helper function to access keychain/keyring
function get_from_keychain
  set -l service $argv[1]
  set -l username $argv[2]
  
  # If GitHub is the service and gh CLI is available, try that first
  if test "$service" = "github"; and type -q gh
    if gh auth status &>/dev/null
      set -l token (gh auth token 2>/dev/null)
      if test $status -eq 0
        echo $token
        return 0
      end
    end
  end
  
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
EOF

  # Make files executable
  chmod 600 "${FLOX_ENV_CACHE}/functions/shell_functions.sh"
  chmod 600 "${FLOX_ENV_CACHE}/functions/shell_functions.fish"

  # Log success
  gum style --foreground 114 "✓ Created shell wrapper functions for secure credential access"
}

# --------------------------------
# Main Logic
# --------------------------------

# Main function to handle all authentication
main() {
  # Bootstrap GitHub authentication (which also configures Git if successful)
  bootstrap_github_auth
  
  # Bootstrap Git authentication (only runs if GitHub auth wasn't successful)
  bootstrap_git_auth
  
  # Bootstrap AWS authentication
  bootstrap_aws_auth
  
  # Generate shell wrapper functions for runtime credential access
  generate_shell_functions
  
  gum style --foreground 114 "✓ Authentication setup complete"
}

# Execute the main function
main
