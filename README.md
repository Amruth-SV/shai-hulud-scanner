# Shai-Hulud Scanner

## Overview

The Shai-Hulud worm is a self-replicating supply chain attack that compromises npm packages by injecting malicious code during installation. This scanner detects infections by checking for known compromised packages, malicious files, and suspicious indicators — covering **both the original Shai-Hulud wave and the newer Sha1-Hulud “Second Coming” Bun-based variant**.

---

## What is Shai-Hulud?

On September 14, 2025, Shai-Hulud — a self-replicating npm worm (malicious code that propagates itself automatically, infecting new targets without direct human intervention) — burst onto the scene by compromising over 180 popular packages in the registry.

Attackers:

- Phished maintainer accounts to obtain npm and GitHub access
- Released tainted versions containing heavily obfuscated JavaScript (a monolithic `bundle.js`)
- Hooked into the `postinstall` phase of `npm install`
- Ran TruffleHog locally to hunt for secrets
- Double-base64-encoded the stolen data and exfiltrated it to attacker-controlled endpoints
- Used the stolen tokens to:
  - Republish additional owned packages
  - Flip private GitHub repositories to public via “-migration” forks

**Sources (v1):**

- https://flyingduck.io/blogs/ctrl-tinycolor-Supply-Chain-Attack  
- https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack  

---

## What is Sha1-Hulud / “The Second Coming”?

In late November 2025, a new wave of attacks appeared in the npm ecosystem, often referred to as **Sha1-Hulud**, **Shai-Hulud 2.0**, or **“Sha1-Hulud: The Second Coming.”**

Instead of a `postinstall` `bundle.js`, this wave focuses on a **fake Bun runtime** theme:

- Compromised packages add a **`preinstall` hook** that runs `node setup_bun.js`
- `setup_bun.js` drops or installs Bun (if needed) and then executes a large, heavily obfuscated payload (`bun_environment.js`, >10 MB)
- The payload:
  - Steals npm, GitHub, and cloud credentials
  - Targets CI/CD environments (especially GitHub Actions) to harvest high-value secrets
  - Uses GitHub repositories as “dropboxes” with descriptions like **“Sha1-Hulud: The Second Coming.”**
  - Stores stolen data in files such as:
    - `actionsSecrets.json`
    - `cloud.json`
    - `contents.json`
    - `environment.json`
    - `truffleSecrets.json`

Multiple vendors have reported **thousands of malicious packages and tens of thousands of GitHub repos** created in this second wave.

**Sources (v2 / Sha1-Hulud, Bun variant):**

- https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24  
- https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised  
- https://www.sonatype.com/blog/the-second-coming-of-shai-hulud-attackers-innovating-on-npm  
- https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains  
- https://www.ox.security/blog/the-second-coming-shai-hulud-is-back-at-it-how-to-protect-your-org  

---

## What is Shai-Hulud-Scanner?

**Shai-Hulud Scanner is a fast, open-source CLI tool to help developers and security teams detect and mitigate both:**

- The original **Shai-Hulud** `bundle.js` npm worm, and  
- The newer **Sha1-Hulud “Second Coming”** fake Bun runtime variant (`setup_bun.js` + `bun_environment.js`).

Motivated by the worm’s rapid spread and impact on the npm ecosystem, this scanner provides proactive threat detection using:

- An up-to-date list of compromised packages
- File and hash checks (including large Bun payloads)
- Git history analysis
- GitHub and GitHub Actions workflow scanning

It’s free, community-driven, and designed to keep projects safe from npm supply chain attacks.

---

## Features

- **Dependency Scanning**
  - Parses `package.json` and lockfiles (npm, Yarn, PNPM)
  - Compares dependencies against a curated `affected-packages.json` list (v1 and v2 waves)

- **File Analysis**
  - Detects known malicious `bundle.js` payloads using SHA-256 hashes
  - Flags suspicious second-wave payloads like `setup_bun.js` and `bun_environment.js`
  - Supports scanning large JavaScript payloads (10MB+)

- **IOC Detection**
  - Searches for high-signal indicators of compromise across source and config files, including:
    - `shai-hulud`, `sha1-hulud`, and “Sha1-Hulud: The Second Coming”
    - Exfil URLs and webhook IDs
    - Suspicious JSON dumps: `actionsSecrets.json`, `truffleSecrets.json`, `cloud.json`, `environment.json`, `contents.json`
    - Traces of TruffleHog-based secret scraping

- **Git Repository Analysis**
  - Scans local Git history for:
    - Suspicious branches and commit messages
    - Added/remotely-injected `bundle.js`, `setup_bun.js`, `bun_environment.js`
    - Potentially malicious GitHub Actions workflows

- **GitHub Integration (Optional)**
  - Given a PAT and org name, scans:
    - Repos for suspicious descriptions (e.g. “Sha1-Hulud: The Second Coming”)
    - Files and workflows for Shai-/Sha1-Hulud markers

- **Workflow Scanning**
  - `--scan-workflows` analyzes `.github/workflows/*.yml` files for shady behaviors:
    - Obfuscated commands
    - Secret dumps into JSON files
    - Potential Sha1-Hulud exfil patterns

- **Secrets Simulation**
  - `--scan-secrets` simulates what the worm would try to steal by scanning for exposed secrets locally

- **Automated Remediation**
  - `--remediate` can automatically remove compromised packages from your project

- **Multi-format Lockfile Support**
  - Works with:
    - `package-lock.json` (npm)
    - `yarn.lock`
    - `pnpm-lock.yaml`

- **JSON Output**
  - Machine-readable results for CI/CD pipelines and security tooling

---

## Installation

### Local Development

```bash
git clone https://github.com/Amruth-SV/shai-hulud-scanner.git
cd shai-hulud-scanner
pip install -r requirements.txt
pip install -e .
```

---

## Usage

### Basic Commands

```bash
# Scan current directory
shai-hulud-scanner

# Scan specific directory
shai-hulud-scanner --dir /path/to/project

# Scan with automatic remediation
shai-hulud-scanner --remediate

# Output results as JSON
shai-hulud-scanner --json

# Show overview of Shai-Hulud worm
shai-hulud-scanner --overview
```

### Advanced Options

```bash
# Skip local git repository scan
shai-hulud-scanner --skip-git

# GitHub organization scan (optional, requires PAT)
shai-hulud-scanner --github-token ghp_xxxxx --org myorg

# Scan for secrets (shows what worm would steal)
shai-hulud-scanner --scan-secrets

# Scan GitHub Actions workflows
shai-hulud-scanner --scan-workflows

# Verbose output
shai-hulud-scanner --verbose
```

### CLI Reference

| Option                       | Description                                          |
| ---------------------------- | ---------------------------------------------------- |
| `-d, --dir <path>`           | Directory to scan (default: current directory)       |
| `-g, --github-token <token>` | GitHub token for org scan (optional)                 |
| `-o, --org <org>`            | GitHub organization to scan (requires token)         |
| `--skip-git`                 | Skip local git repository analysis                   |
| `--remediate`                | Automatically uninstall bad dependencies             |
| `--scan-secrets`             | Scan for exposed secrets (TruffleHog simulation)     |
| `--scan-workflows`           | Scan GitHub Actions workflows for malicious patterns |
| `--json`                     | Output results as JSON                               |
| `--verbose`                  | Enable detailed logging                              |
| `--overview`                 | Display overview of Shai-Hulud worm                  |
| `--version`                  | Show version information                             |
| `--help`                     | Display help information                             |

---

## Remediation Steps

When issues are detected:

1. **Rotate Credentials**  
   Immediately rotate all tokens (npm, GitHub, cloud providers, CI secrets, etc.).

2. **Remove Bad Packages**  
   Use the `--remediate` flag or manually uninstall compromised dependencies.

3. **Clean Install**  
   Remove `node_modules` and reinstall dependencies from a clean lockfile.

4. **Verify**  
   Re-run the scanner to confirm cleanup and ensure no residual indicators remain.

5. **Monitor**  
   Review recent commits, GitHub Actions runs, and access logs for unauthorized changes or suspicious activity.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make changes and test functionality
4. Test the scanner (`python -m src.cli`)
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/Amruth-SV/shai-hulud-scanner.git
cd shai-hulud-scanner
pip install -r requirements.txt
pip install -e .
python -m src.cli --help
```

---

## Community

Researchers, please help update `affected-packages.json` and improve detection logic for new variants (Shai-Hulud, Sha1-Hulud, and future copycats). Submit PRs with reliable sources for additions — we review and merge quickly to protect everyone.

---

## Support

* **Issues**: [https://github.com/Amruth-SV/shai-hulud-scanner/issues](https://github.com/Amruth-SV/shai-hulud-scanner/issues)
* **Documentation**: [https://github.com/Amruth-SV/shai-hulud-scanner/wiki](https://github.com/Amruth-SV/shai-hulud-scanner/wiki)
* **Updates**: Watch the repository and releases for the latest threat intelligence

---

## Author

**Amruth** – [GitHub](https://github.com/Amruth-SV) – [CloudSEK](https://cloudsek.com)

**Gokul Peetu**
