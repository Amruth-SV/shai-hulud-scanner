#!/usr/bin/env python3
"""
Affected list fetcher service for Shai-Hulud Scanner
"""

import json
import os
import requests
from pathlib import Path
from ..constants import DEFAULT_BADLIST_URL, HTTP_TIMEOUT
from ..utils.logger import log

def fetch_remote_affected_list(url=DEFAULT_BADLIST_URL):
    """
    Fetches fresh affected list from remote URL every time the tool runs.
    Returns affected list dictionary
    """
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        
        affected_list = response.json()
        
        # Validate structure
        if not isinstance(affected_list, dict):
            raise ValueError("Invalid affected list format")
        
        package_count = len([k for k in affected_list.keys() if not k.startswith('_')])
        log.info(f"Fetched latest affected-packages.json from remote ({package_count} packages).")
        
        return affected_list
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error: {e}")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse remote affected-packages.json: {e}")
    except Exception as e:
        raise Exception(f"Failed to fetch remote affected list: {e}")

def load_local_badlist():
    """
    Loads affected list from local file.
    Returns affected list dictionary
    """
    try:
        # Look for local affected list file
        script_dir = Path(__file__).parent.parent.parent
        local_affected_list_path = script_dir / 'affected-packages.json'

        with open(local_affected_list_path, 'r', encoding='utf-8') as f:
            local_affected_list = json.load(f)

        package_count = len([k for k in local_affected_list.keys() if not k.startswith('_')])
        log.info(f"📦 Using local affected-packages.json ({package_count} packages).")

        return local_affected_list

    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error("Failed to load local affected-packages.json. Cannot proceed without threat intelligence.")
        raise Exception("No affected list available - ensure affected-packages.json exists and is readable")

def get_badlist(offline=False):
    """
    Gets affected list by fetching fresh data on every run, with local fallback only if remote fails.
    If offline=True, skips remote fetch and uses local file directly.
    Returns affected list dictionary
    """
    if offline:
        log.info("Offline mode enabled - using local affected-packages.json")
        return load_local_badlist()

    try:
        # Always try to fetch fresh data first
        return fetch_remote_affected_list()
    except Exception as error:
        # Only use local file if remote fetch fails
        log.warn(f"Remote fetch failed: {error}")
        log.info("Falling back to local affected-packages.json...")
        return load_local_badlist()
