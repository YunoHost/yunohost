alias pre-commit := check
alias lint := check

# Run the pre-commit checks
check:
  ./maintenance/shfmt.sh --diff
