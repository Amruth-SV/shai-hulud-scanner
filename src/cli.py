#!/usr/bin/env python3
"""
Main CLI for Shai-Hulud Scanner
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from colorama import Fore, Style

from .services.badlist_fetcher import get_badlist
from .scanners.dependency_scanner import scan_dependencies
from .scanners.file_scanner import scan_files
from .scanners.github_scanner import scan_github
from .scanners.git_scanner import scan_git_repository
from .utils.logger import log
from .utils.ui import (
    create_header,
    create_results_section,
    create_summary,
    create_recommendations,
    create_threat_details
)
from .constants import VERSION

def main():
    """Main CLI for Shai-Hulud Scanner."""
    parser = argparse.ArgumentParser(
        prog='shai-hulud-scanner',
        description='CLI scanner for Shai-Hulud npm worm infections'
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument(
        '-d', '--dir',
        default=os.getcwd(),
        help='Directory to scan (default: current directory)'
    )
    parser.add_argument(
        '-g', '--github-token',
        help='GitHub token for org scan (optional)'
    )
    parser.add_argument(
        '-o', '--org',
        help='GitHub org to scan (requires token)'
    )
    parser.add_argument(
        '--skip-git',
        action='store_true',
        help='Skip local git repository scan'
    )
    parser.add_argument(
        '--remediate',
        action='store_true',
        help='Auto-uninstall bad deps and remove suspicious files'
    )
    parser.add_argument(
        '--scan-secrets',
        action='store_true',
        help='Scan for secrets (TruffleHog simulation)'
    )
    parser.add_argument(
        '--scan-workflows',
        action='store_true',
        help='Scan GitHub Actions workflows'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output as JSON report'
    )
    parser.add_argument(
        '--overview',
        action='store_true',
        help='Display overview of Shai-Hulud worm'
    )
    parser.add_argument(
        '--offline',
        action='store_true',
        help='Use local affected-packages.json without fetching from remote'
    )

    args = parser.parse_args()
    
    # Handle overview option
    if args.overview:
        print(f"{Fore.CYAN}Shai-Hulud Worm Overview:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}On September 14, 2025, Shai-Hulud—a self-replicating npm worm (malicious code that propagates itself automatically, infecting new targets without direct human intervention)—burst onto the scene by compromising over 180 popular packages in the registry; adversaries began by phishing maintainer accounts, then released tainted versions containing heavily obfuscated JavaScript (notably a monolithic `bundle.js`) that executed during the `postinstall` phase of `npm install`, after which the payload ran TruffleHog to hunt for secrets in the developer's environment, double-base64-encoded the stolen data for stealth and exfiltrated it to attacker-controlled endpoints, and finally amplified its reach by republishing additional owned packages and even flipping private GitHub repositories to public via \"-migration\" forks.{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}\nSources:{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}* https://flyingduck.io/blogs/ctrl-tinycolor-Supply-Chain-Attack{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}* https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack{Style.RESET_ALL}")
        sys.exit(0)
    
    # Set up logging
    if args.verbose:
        log.verbose = True
    
    directory = os.path.abspath(args.dir)
    is_json = args.json
    start_time = time.time()
    
    results = {
        'scannedDir': directory,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'badDeps': [],
        'suspiciousFiles': [],
        'suspiciousScripts': [],
        'githubIssues': [],
        'gitIssues': [],
        'totalIssues': 0
    }
    
    # Check if it's a git repository
    is_git_repo = os.path.exists(os.path.join(directory, '.git'))
    
    if not is_json:
        # Show clean header
        print(create_header(directory, VERSION, is_git_repo))
    
    if args.verbose and not is_json:
        log.info('Verbose mode enabled.')
    
    try:
        # Load badlist
        bad_packages = get_badlist(offline=args.offline)
        
        # Run scanners
        dep_results = scan_dependencies(directory, bad_packages, is_json)
        results['badDeps'] = dep_results['badDeps']
        results['totalScanned'] = dep_results['totalScanned']
        results['totalIssues'] += len(results['badDeps'])
        
        file_results = scan_files(directory, is_json)
        results['suspiciousFiles'] = file_results['suspiciousFiles']
        results['suspiciousScripts'] = file_results['suspiciousScripts']
        results['totalIssues'] += len(results['suspiciousFiles']) + len(results['suspiciousScripts'])
        
        # Local git repository scan (no API required)
        if not args.skip_git:
            git_results = scan_git_repository(directory, is_json)
            results['gitIssues'] = git_results['gitIssues']
            if 'gitError' in git_results:
                results['gitError'] = git_results['gitError']
            results['totalIssues'] += len(results['gitIssues'])
        
        # Optional GitHub organization scan (requires PAT)
        if args.github_token and args.org:
            github_results = scan_github(args.github_token, args.org, is_json)
            results['githubIssues'] = github_results['githubIssues']
            if 'githubError' in github_results:
                results['githubError'] = github_results['githubError']
            results['totalIssues'] += len(results['githubIssues'])
        
        duration = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        # Output
        if is_json:
            print(json.dumps(results, indent=2))
            sys.exit(1 if results['totalIssues'] > 0 else 0)
        
        # Show clean results
        print(create_results_section(results, duration))
        
        # Show detailed threat information if any issues found
        if results['totalIssues'] > 0:
            print(create_threat_details(results))
            
            # Auto-remediation
            if results['badDeps'] and args.remediate:
                package_names = ' '.join([dep['name'] for dep in results['badDeps']])
                remediated_count = len(results['badDeps'])
                print(f"{Fore.YELLOW}[INF]{Style.RESET_ALL} Auto-remediation initiated...")
                
                try:
                    import subprocess
                    subprocess.run(['npm', 'uninstall'] + [dep['name'] for dep in results['badDeps']], 
                                 cwd=directory, check=True)
                    print(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Bad dependencies uninstalled successfully")
                    
                    # Show post-remediation summary
                    print(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Remediation complete - removed {remediated_count} compromised packages")
                    print(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Project dependencies cleaned successfully")
                    print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Next: run 'npm install' to reinstall clean dependencies")
                    print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Consider running 'npm audit' for additional security checks")
                    
                    # Exit successfully after remediation
                    sys.exit(0)
                except subprocess.CalledProcessError as error:
                    print(f"{Fore.RED}[ERR]{Style.RESET_ALL} Remediation failed: {error}")
        
        # Show summary and recommendations
        print(create_summary(results, duration))
        print(create_recommendations())
        
        sys.exit(1 if results['totalIssues'] > 0 else 0)
    
    except Exception as error:
        log.error(f'Scan failed: {error}')
        sys.exit(1)

if __name__ == '__main__':
    main()
