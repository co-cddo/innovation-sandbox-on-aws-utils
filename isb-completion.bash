_isb_completions() {
  local cur prev commands
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  commands="assign terminate templates create-user create-pool-account force-release close-account clean-console help"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
    return
  fi

  case "${COMP_WORDS[1]}" in
    create-user)
      COMPREPLY=($(compgen -W "--firstname= --lastname= --email= --displayname= --preapproved" -- "$cur"))
      ;;
    create-pool-account)
      COMPREPLY=($(compgen -W "--num=" -- "$cur"))
      ;;
    force-release)
      COMPREPLY=($(compgen -W "--all" -- "$cur"))
      ;;
    close-account)
      COMPREPLY=($(compgen -W "--quarantined --limit= --dry-run" -- "$cur"))
      ;;
    clean-console)
      COMPREPLY=($(compgen -W "--ou --account --all-roles --dry-run --no-cache --clear-cache" -- "$cur"))
      ;;
  esac
}

complete -o nospace -F _isb_completions isb
