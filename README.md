# Recon 

A modular, Python-based reconnaissance framework with built-in rate limiting, custom wordlist support, and automated tool installation.

## Features

- **Modular Architecture**: Plugin-based system for easy expansion
- **Global Rate Limiting**: Prevent IP blocking with configurable rate limits
- **Custom Word Lists**: Flexible wordlist management for directory brute forcing
- **Automated Tool Installation**: One-command setup of all required tools
- **Multi-Platform Support**: Linux, macOS compatibility
- **TUI/CLI Interface**: Both terminal user interface and command-line usage
- **Smart Tool Detection**: Enhanced tool checking across multiple installation methods
- **Configuration Management**: YAML-based configuration with flexible settings

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Modules](#modules)
- [Rate Limiting](#rate-limiting)
- [Word Lists](#word-lists)
- [Tool Management](#tool-management)
- [Advanced Usage](#advanced-usage)

## Installation

### Prerequisites

Install the required system packages based on your operating system:

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y git golang-go python3-pip libpcap-dev
```

#### Fedora/CentOS/RHEL
```bash
sudo dnf install -y git golang python3-pip libpcap-devel
```

#### Arch Linux
```bash
sudo pacman -S git go python-pip libpcap
```

#### macOS
```bash
brew install git go python3 libpcap
```

### Automated Installation

Clone the repository and install all required tools automatically:

```bash
git clone <repository-url>
cd recon
python3 main.py --install
```

## Quick Start

1. Check Installation Status
```bash
python3 main.py --check-tools
```

2. Run Basic Reconnaissance
```bash
python3 main.py recon --project ./target --subs --alive -v
```

3. Run Full Recon Chain
```bash
python3 main.py recon --project ./target --full -v
```

4. Use TUI Interface
```bash
python3 main.py
```

## Configuration

The framework uses `config.yaml` for configuration. Key sections:

### Rate Limiting
```yaml
rate_limiting:
  global_rps: 10        # Global requests per second
  burst_capacity: 50     # Burst capacity for token bucket
  tool_limits:          # Per-tool overrides
    subfinder: 25
    httpx: 50
    nuclei: 30
    dirsearch: 20
```

### Word Lists
```yaml
wordlists:
  default_dirsearch: "/usr/share/wordlists/OneListForAll/onelistforallshort.txt"
  custom_directories:
    - "./wordlists"
    - "~/.config/recon/wordlists"
    - "/usr/share/wordlists"
  predefined_sizes:
    small: "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    medium: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    large: "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
```

## Usage

### Command Line Interface

#### Basic Commands
```bash
# Help
python3 main.py --help

# Check tool installation
python3 main.py --check-tools

# Install all tools
python3 main.py --install

# Interactive installation
python3 main.py --install-interactive
```

#### Reconnaissance Module

```bash
# Individual steps
python3 main.py recon --project ./target --subs -v
python3 main.py recon --project ./target --alive -v
python3 main.py recon --project ./target --dirs -v
python3 main.py recon --project ./target --nuclei -v

# Full reconnaissance chain
python3 main.py recon --project ./target --full -v

# With custom settings
python3 main.py recon --project ./target --full \
  --global_rps 5 \
  --wordlist ./custom-wordlist.txt \
  --ports 443,80,8080
```

#### Rate Limiting Controls
```bash
# Override global rate limit
python3 main.py recon --project ./target --full --global_rps 15

# Disable all rate limiting
python3 main.py recon --project ./target --full --disable_rate_limiting
```

#### Custom Word Lists
```bash
# Use custom wordlist
python3 main.py recon --project ./target --dirs --wordlist ./custom.txt

# Use predefined size
python3 main.py recon --project ./target --dirs --wordlist_size medium

# Use custom wordlist directory
python3 main.py recon --project ./target --dirs --wordlist_dir ./my-wordlists
```

### TUI Interface

Launch the terminal user interface:

```bash
python3 main.py
```

Navigate with arrow keys, select modules, and configure options interactively.

## Modules

### Recon Module (`recon`)

Primary reconnaissance module with the following stages:

#### Subdomain Enumeration (`--subs`)
- Uses `subfinder` with wildcard scope lists
- Configurable rate limiting
- Output: `subs.txt`

#### Alive Checking (`--alive`) 
- Uses `httpx` to probe discovered domains
- Custom port configuration
- Output: `alive.txt`

#### Port Scanning (`--ports_scan`)
- Uses `naabu` for fast port scanning
- Falls back to `nmap` for detailed scanning
- Output: `ports.txt`

#### Directory Brute Force (`--dirs`)
- Uses `dirsearch` with configurable wordlists
- Custom wordlist support
- Output: `dirsearch.txt`

#### Parameter Mining (`--params`)
- Uses `gau` for URL discovery
- Uses `uro` for parameter extraction
- Output: `params_filtered.txt`

#### Secret Scanning (`--secrets`)
- Uses `SecretFinder` on JavaScript files
- Output: `secrets.txt`

#### Vulnerability Scanning (`--nuclei`)
- Uses `nuclei` with custom templates
- Runs on filtered parameters
- Output: `nuclei.txt`

### Secrets Module (`secrets`)

Placeholder module for secret scanning functionality.

## Rate Limiting

The framework implements a **token bucket algorithm** for global rate limiting.

### Key Concepts

#### `global_rps` (Global Requests Per Second)
- Controls the **steady-state** request rate
- Prevents IP blocking and server overload
- Default: 10 requests per second

#### `burst_capacity` 
- Controls **short-term bursts** above normal rate
- Allows temporary traffic spikes
- Default: 50 requests

### How It Works

1. **Token Accumulation**: Tokens accumulate at `global_rps` rate
2. **Token Spending**: Each request consumes one token
3. **Rate Limiting**: Wait when no tokens available
4. **Tool Overrides**: Per-tool limits can override global settings

### Examples

```yaml
# Conservative (safe from blocking)
rate_limiting:
  global_rps: 5
  burst_capacity: 20

# Balanced (default)
rate_limiting:
  global_rps: 10
  burst_capacity: 50

# Aggressive (fast scanning)
rate_limiting:
  global_rps: 25
  burst_capacity: 100
```

### Runtime Overrides

```bash
# Override global rate limit
python3 main.py recon --project ./target --full --global_rps 3

# Disable rate limiting completely
python3 main.py recon --project ./target --full --disable_rate_limiting
```

## Word Lists

Flexible wordlist management for directory brute forcing.

### Wordlist Sources

#### 1. Custom Paths (Highest Priority)
```bash
python3 main.py recon --project ./target --dirs --wordlist ./my-list.txt
```

#### 2. Predefined Sizes
```bash
python3 main.py recon --project ./target --dirs --wordlist_size small   # small/medium/large
```

#### 3. Custom Directories
```bash
python3 main.py recon --project ./target --dirs --wordlist_dir ./wordlists
```

#### 4. Default Wordlist (Fallback)
Uses the configured default if no other wordlist is specified.

### Wordlist Validation

The framework validates wordlists before use:
- **Minimum size**: 10 bytes
- **Maximum size**: 1,000,000 bytes  
- **Existence check**: File must exist

### Directory Search Order

1. Custom path (if specified)
2. Custom directories → `{size}.txt`
3. Predefined sizes path
4. Default wordlist path

## Tool Management

### Tool Installation System

Automated installation of reconnaissance tools with smart detection.

#### Supported Tool Types

##### Go Tools
- `subfinder` - Subdomain enumeration
- `naabu` - Port scanning  
- `httpx` - HTTP probing
- `nuclei` - Vulnerability scanning
- `gau` - URL gathering
- `uro` - Parameter extraction

##### Git Tools  
- `dirsearch` - Directory brute force
- `SecretFinder` - JavaScript secret scanning

##### System Tools
- `nmap` - Network scanning

### Installation Commands

```bash
# Check what's installed
python3 main.py --check-tools

# Install all tools automatically
python3 main.py --install

# Interactive installation with confirmation
python3 main.py --install-interactive
```

### Installation Status

```bash
$ python3 main.py --check-tools

Tool Installation Status: 3/9
==================================================
  ✓ subfinder (go)
  ✗ naabu (go)  
  ✗ httpx-toolkit (go)
  ✗ nuclei (go)
  ✓ dirsearch (git)
  ✗ gau (go)
  ✗ uro (go)
  ✓ secretfinder (git)
  ✗ nmap (system)

Missing tools: naabu, httpx-toolkit, nuclei, gau, uro, nmap
Run with --install-interactive to install them.
```

### Smart Tool Detection

The framework checks multiple installation methods:
- **PATH detection**: Standard executable lookup
- **Go binaries**: Custom path checking in `~/.local/bin/`
- **Python packages**: Pip package verification
- **Git repositories**: Local clone checking
- **System packages**: Distribution-specific detection

## Advanced Usage

### Project Structure

```
target/
├── alive.txt              # Live domains
├── subs.txt               # All subdomains
├── ports.txt              # Open ports  
├── dirsearch.txt           # Directories found
├── params_filtered.txt     # URL parameters
├── secrets.txt            # Secrets found
├── nuclei.txt             # Vulnerabilities
├── wild.txt               # Wildcard scope
└── logs/
    └── recon_*.log        # Execution logs
```

### Custom Configuration

Create `~/.config/recon/config.yaml` for user-specific settings:

```yaml
framework_name: Recon

# User preferences
rate_limiting:
  global_rps: 15
  burst_capacity: 75

wordlists:
  custom_directories:
    - "~/my-wordlists"
    - "/opt/wordlists"

installation:
  go_bin_dir: "~/bin"  # Custom Go binary location
```


### Log Files

Log files are stored within the project directory that you used. 
`ex: /bounty/target/recon/logs`

### Module Development

Create new modules in `modules/` directory:

```python
module_name = "MyModule"
module_key = "X"
cli_name = "mymodule"

def register_args(parser):
    parser.add_argument("--option", help="My option")

def run_cli(args, config):
    # Module logic here
    pass

def run_tui(stdscr, config):
    # TUI implementation here
    pass
```

## License

[License information - e.g., MIT License]

