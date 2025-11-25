#!/usr/bin/env python3
"""
Lockfile parsing utilities for different package managers
"""

import json
import os
import re
from pathlib import Path

import yaml

from .logger import log

YARN_BERRY_PROTOCOL_RE = re.compile(
    r'^(?P<name>(?:@[^/@]+/)?[^@/]+)@(?:npm|patch|workspace|link|file|exec|git|http|https):'
)

def parse_lockfile(directory):
    """
    Parse lockfiles for npm, Yarn, and PNPM to extract dependencies
    Returns list of {name, version} dictionaries
    """
    dependencies = []
    dir_path = Path(directory)
    
    # Try npm package-lock.json
    npm_lock = dir_path / 'package-lock.json'
    if npm_lock.exists():
        dependencies.extend(parse_npm_lockfile(npm_lock))
    
    # Try Yarn yarn.lock
    yarn_lock = dir_path / 'yarn.lock'
    if yarn_lock.exists():
        dependencies.extend(parse_yarn_lockfile(yarn_lock))
    
    # Try PNPM pnpm-lock.yaml
    pnpm_lock = dir_path / 'pnpm-lock.yaml'
    if pnpm_lock.exists():
        dependencies.extend(parse_pnpm_lockfile(pnpm_lock))
    
    return dependencies

def parse_npm_lockfile(lockfile_path):
    """Parse npm package-lock.json"""
    dependencies = []
    
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            lock_data = json.load(f)
        
        # Handle different package-lock.json formats
        if 'packages' in lock_data:
            # npm v7+ format
            for package_path, package_info in lock_data['packages'].items():
                if package_path == '':  # Skip root package
                    continue
                
                name = package_path.split('node_modules/')[-1]
                version = package_info.get('version', '0.0.0')
                
                if name and version:
                    dependencies.append({'name': name, 'version': version})
        
        elif 'dependencies' in lock_data:
            # npm v6 format
            dependencies.extend(extract_npm_v6_deps(lock_data['dependencies']))
        
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        log.debug(f"Failed to parse npm lockfile {lockfile_path}: {e}")
    
    return dependencies

def extract_npm_v6_deps(deps_dict):
    """Recursively extract dependencies from npm v6 format"""
    dependencies = []
    
    for name, info in deps_dict.items():
        version = info.get('version', '0.0.0')
        dependencies.append({'name': name, 'version': version})
        
        # Recursively process nested dependencies
        if 'dependencies' in info:
            dependencies.extend(extract_npm_v6_deps(info['dependencies']))
    
    return dependencies

def parse_yarn_lockfile(lockfile_path):
    """Parse Yarn yarn.lock file (classic v1 or Berry v2+)"""
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        return []

    # Yarn Berry (2+) uses strict YAML with __metadata section
    try:
        lock_data = yaml.safe_load(content)
        if isinstance(lock_data, dict) and any(
            meta_key in lock_data for meta_key in ('__metadata', '__metadata__')
        ):
            return _parse_yarn_berry_lock(lock_data)
    except yaml.YAMLError:
        pass

    # Fallback to Yarn classic parser
    return _parse_yarn_classic_lock(content)


def _parse_yarn_classic_lock(content):
    """Parse Yarn 1.x lockfiles that use the legacy format"""
    pattern = re.compile(
        r'^"?([^@\s]+)@[^"]*"?:\s*\n(?:[ \t]+.*\n)*?[ \t]+version\s+"([^"]+)"',
        re.MULTILINE,
    )
    return [{'name': name, 'version': version} for name, version in pattern.findall(content)]


def _parse_yarn_berry_lock(lock_data):
    """Parse Yarn 2+/Berry YAML lockfiles"""
    dependencies = []
    meta_keys = {'__metadata', '__metadata__'}
    for descriptor, entry in lock_data.items():
        if descriptor in meta_keys or not isinstance(entry, dict):
            continue

        version = entry.get('version')
        if not version:
            continue

        name = _extract_yarn_berry_name(descriptor)
        if not name:
            continue

        dependencies.append({'name': name, 'version': str(version)})
    return dependencies


def _extract_yarn_berry_name(descriptor):
    """
    Extract package name from a Yarn 2 descriptor (may contain multiple descriptors separated by commas)
    """
    first_descriptor = descriptor.split(',')[0].strip().strip('"').strip("'")
    match = YARN_BERRY_PROTOCOL_RE.match(first_descriptor)
    if match:
        return match.group('name')

    if first_descriptor.startswith('@'):
        second_at = first_descriptor.find('@', 1)
        if second_at != -1:
            return first_descriptor[:second_at]

    if '@' in first_descriptor:
        return first_descriptor.split('@', 1)[0]

    return first_descriptor

def parse_pnpm_lockfile(lockfile_path):
    """Parse PNPM pnpm-lock.yaml file"""
    dependencies = []
    
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            lock_data = yaml.safe_load(f)
        
        # PNPM stores dependencies in 'packages' section
        packages = lock_data.get('packages', {})
        
        for package_spec, package_info in packages.items():
            # Package spec format: /package/version or /package/version_hash
            if package_spec.startswith('/'):
                parts = package_spec[1:].split('/')
                if len(parts) >= 2:
                    name = '/'.join(parts[:-1])
                    version_part = parts[-1]
                    # Extract version (remove hash if present)
                    version = version_part.split('_')[0]
                    
                    dependencies.append({'name': name, 'version': version})
    
    except (yaml.YAMLError, FileNotFoundError, KeyError) as e:
        log.debug(f"Failed to parse PNPM lockfile {lockfile_path}: {e}")
    
    return dependencies

def clean_version(version):
    """Clean version string by removing prefixes like ^, ~, etc."""
    return re.sub(r'^[^\d]+', '', version)
