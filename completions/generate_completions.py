#!/usr/bin/env python3
"""Generate shell completion scripts for Git2in CLI."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.cli.main import app
import typer

def generate_completions():
    """Generate completion scripts for all supported shells."""
    shells = ["bash", "zsh", "fish"]
    
    for shell in shells:
        print(f"Generating {shell} completion...")
        
        # Get completion script
        completion_script = typer.completion.get_completion(app, shell_complete=shell)
        
        # Save to file
        output_file = Path(__file__).parent / f"git2in.{shell}"
        with open(output_file, "w") as f:
            f.write(completion_script)
        
        print(f"  Saved to: {output_file}")
    
    print("\nCompletion scripts generated successfully!")
    print("\nTo install completions:")
    print("  Bash: source completions/git2in.bash")
    print("  Zsh:  source completions/git2in.zsh")
    print("  Fish: source completions/git2in.fish")

if __name__ == "__main__":
    generate_completions()