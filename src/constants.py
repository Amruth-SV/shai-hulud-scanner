#!/usr/bin/env python3
"""
Constants for Shai-Hulud / Sha1-Hulud Scanner.

Covers:
- V1 Shai-Hulud (Sept 2025) bundle.js worm
- V2 "Sha1-Hulud: The Second Coming" fake Bun runtime (Nov 2025)
"""

import re

# -----------------------------------------------------------------------------
# File hashes
# -----------------------------------------------------------------------------

# V1: Known malicious bundle.js hash from original Shai-Hulud worm (SHA-256)
BUNDLE_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

# V2: Known Bun payload hashes from Sha1-Hulud "Second Coming" campaign (SHA-1)
# Source: public research from Wiz / Aikido on setup_bun.js & bun_environment.js
SECOND_WAVE_BUN_HASHES = {
    "bun_environment.js": [
        "d60ec97eea19fffb4809bc35b91033b52490ca11",
        "3d7570d14d34b0ba137d502f042b27b0f37a59fa",
    ],
    "setup_bun.js": [
        "d1829b4708126dcc7bea7437c04d1f10eacd4a16",
    ],
}

# -----------------------------------------------------------------------------
# Suspicious lifecycle scripts (postinstall / preinstall)
# -----------------------------------------------------------------------------
# This is used against package.json install-time scripts. We keep the original
# name (SUSPICIOUS_POSTINSTALL) for backwards compatibility, but it now
# covers both postinstall and preinstall style payloads.

SUSPICIOUS_POSTINSTALL = re.compile(
    r"("
    r"node\s+bundle\.js|"          # V1 worm payload
    r"node\s+setup_bun\.js|"       # V2 fake Bun runtime installer
    r"setup_bun\.js|"              # direct execution
    r"bun_environment\.js|"        # 10MB obfuscated Bun payload
    r"trufflehog|"                 # abused secret scanner
    r"webhook\.site|"              # V1 exfil endpoint
    r"exfiltrat"                   # generic exfil keyword
    r")",
    re.IGNORECASE,
)

# -----------------------------------------------------------------------------
# High-signal IoCs that can appear in files, scripts, or repo metadata
# -----------------------------------------------------------------------------

SUSPICIOUS_IOCS = re.compile(
    r"("
    # Original wave (Sept 2025)
    r"webhook\.site|"                                  # exfil service
    r"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|"           # specific webhook ID
    r"shai[-_ ]?hulud|"                                # generic Shai-Hulud markers
    # Second wave (Nov 2025 - \"Sha1-Hulud: The Second Coming\")
    r"sha1[-_ ]?hulud|"                                # new spelling / branding
    r"Sha1-Hulud:\s*The Second Coming|"                # repo description
    r"SHA1HULUD|"                                      # self-hosted runner name
    # Malicious workflows and branches
    r"shai-hulud-workflow\.ya?ml|"                     # V1 workflow
    r"\.github/workflows/discussion\.ya?ml|"           # V2 backdoor workflow
    r"\.github/workflows/formatter_[0-9]+\.ya?ml|"     # V2 exfil formatter workflow
    # Exfiltrated data files created by the worm
    r"actionsSecrets\.json|"                           # GitHub secrets dump
    r"truffleSecrets\.json|"                           # TruffleHog-discovered secrets
    r"cloud\.json|"                                    # cloud secrets (AWS/GCP/Azure)
    r"environment\.json|"                              # env vars from victim machine
    r"contents\.json|"                                 # host info + GitHub token
    # Tooling / generic strings reused across waves
    r"trufflehog"                                      # abused for local secret scanning
    r")",
    re.IGNORECASE,
)

# Convenience lists for any future heuristics (not required by existing code,
# but useful to have centralised here).
SUSPICIOUS_FILENAMES = [
    "bundle.js",
    "setup_bun.js",
    "bun_environment.js",
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    "actionsSecrets.json",
    "shai-hulud-workflow.yml",
    "shai-hulud-workflow.yaml",
    "discussion.yaml",
]

SUSPICIOUS_WORKFLOW_PATTERNS = re.compile(
    r"\.github/workflows/(?:"
    r"shai-hulud-workflow\.ya?ml|"
    r"discussion\.ya?ml|"
    r"formatter_[0-9]+\.ya?ml"
    r")",
    re.IGNORECASE,
)

# -----------------------------------------------------------------------------
# Scanner metadata / settings
# -----------------------------------------------------------------------------

# Bump for second-wave coverage
VERSION = "2.0.0"

# Default affected list URL (you can keep this JSON updated with both waves)
DEFAULT_BADLIST_URL = (
    "https://raw.githubusercontent.com/Amruth-SV/shai-hulud-scanner/main/"
    "affected-packages.json"
)

# Timeout for HTTP requests (seconds)
HTTP_TIMEOUT = 10

# Maximum file size to scan (bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
