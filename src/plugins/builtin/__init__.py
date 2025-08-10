"""Built-in plugins for Git2in."""

from src.plugins.builtin.branch_protection import BranchProtectionPlugin
from src.plugins.builtin.commit_validation import CommitValidationPlugin

__all__ = [
    "BranchProtectionPlugin",
    "CommitValidationPlugin",
]