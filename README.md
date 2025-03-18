# ldapcheck

A lightweight LDAP signing and channel binding enumeration and testing tool designed for Active Directory environments. 

## Features

- Domain Controller discovery via DNS
- NTLM authentication support
- Support for both password and hash-based authentication (Pass-the-Hash)
- Configurable connection timeouts
- Multiple output formats for discovered DCs and relay targets
- File-based target input support

## Installation

```bash
go install github.com/DriftSec/ldapcheck@latest
```

Or build from source:

```bash
git clone https://github.com/DriftSec/ldapcheck.git
cd ldapcheck
go build
```

## Usage

Basic usage examples:

```bash
# Test single target with username/password
ldapcheck -t dc.domain.com -u user@domain.com -p password

# Test single target with NTLM hash
ldapcheck -t dc.domain.com -u user@domain.com -H <NTLM_HASH>

# Discover DCs for a domain
ldapcheck -T domain.com

# Test multiple targets from a file
ldapcheck -t targets.txt -u user@domain.com -p password
```

### Command Line Options

```
ldapcheck -h

  -H string
        user NTLM hash
  -T string
        Query this domain for LDAP targets
  -dc-out string
        output file for discovered DCs (one per line)
  -p string
        user password
  -relay-out string
        output file for relay targets (format: ldap[s]://host)
  -t string
        target address or file containing targets
  -timeout duration
        timeout for LDAP connections (default 5s)
  -u string
        username, formats: user@domain or domain\user
```

## Output Formats

### DC List Output (-dc-out)

The `-dc-out` option generates a list of discovered Domain Controllers. Each line in the output file represents a single DC.

Example output:

```
dc1.domain.com
dc1.domain.com
dc2.domain.com
dc2.domain.com
```

### Relay List Output (-relay-out)

The `-relay-out` option generates a list of relay targets. Each line in the output file represents a single relay target for use with ntlmrelayx.py

Example output:

```
ldap://dc1.domain.com
ldaps://dc1.domain.com
ldap://dc2.domain.com
```