#!/usr/bin/env bash
# Bash completion for the firewall-tui command.
#
# Completes the bare positional HOST argument (the firewall/host names, read
# from the ruleset directory in the config) and the --config / --fwdir /
# --includedir options.
#
# Usage — source this file in your shell rc, e.g.:
#     . /home/mark/projects/firewall-tui/firewall-tui-completion.bash
# or symlink/copy it into /etc/bash_completion.d/ and start a new shell.

# Directory containing this script (used as the default config fallback).
_fw_tui_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly _fw_tui_script_dir

# _fw_tui_dir — resolve the ruleset directory, honouring any --config / --fwdir
# already typed on the command line. Prints the directory (possibly empty).
# Args: none. Globals: COMP_WORDS, COMP_CWORD.
_fw_tui_dir() {
   local i opt config fwdir
   for ((i = 1; i < COMP_CWORD; i++)); do
      opt="${COMP_WORDS[i]}"
      case "$opt" in
         --config) config="${COMP_WORDS[i + 1]}" ;;
         --fwdir) fwdir="${COMP_WORDS[i + 1]}" ;;
      esac
   done
   # --fwdir directly names the ruleset directory, so it wins.
   if [[ -n "$fwdir" ]]; then
      printf '%s' "$fwdir"
      return
   fi
   # Resolve the config file: explicit, then per-user, then project default.
   if [[ -z "$config" ]]; then
      if [[ -f "$HOME/.firewall-tui.conf" ]]; then
         config="$HOME/.firewall-tui.conf"
      else
         config="${_fw_tui_script_dir}/firewall-tui.conf"
      fi
   fi
   # Print the 'dir' key from the [firewall] section only.
   awk -F= '
      /^[[:space:]]*\[[[:space:]]*firewall[[:space:]]*\]/ { in_fw = 1; next }
      /^[[:space:]]*\[/ { in_fw = 0 }
      in_fw && /^[[:space:]]*dir[[:space:]]*=/ {
         sub(/^[[:space:]]*dir[[:space:]]*=[[:space:]]*/, "")
         gsub(/[[:space:]]+$/, "")
         print
         exit
      }
   ' "$config" 2>/dev/null
}

# _fw_tui_hosts — complete the firewall (host) names for the bare positional.
# Args: cur (the current word to complete). Sets COMPREPLY.
_fw_tui_hosts() {
   local dir
   dir="$(_fw_tui_dir)"
   if [[ -z "$dir" || ! -d "$dir" ]]; then
      return 1
   fi
   # Firewall files are the non-dot, non-'db' files in the ruleset directory.
   COMPREPLY=( $(compgen -W "$(
      find "$dir" -maxdepth 1 -type f ! -name '.*' ! -name 'db' \
         -printf '%f ' 2>/dev/null
   )" -- "$1") )
}

# _firewall_tui — main completion entry point for the command.
_firewall_tui() {
   local cur prev
   cur="${COMP_WORDS[COMP_CWORD]}"
   prev="${COMP_WORDS[COMP_CWORD - 1]}"

   # Complete the value of a typed option.
   case "$prev" in
      --config)
         COMPREPLY=( $(compgen -f -X '!*.conf' -- "$cur") )
         return
         ;;
      --fwdir|--includedir)
         COMPREPLY=( $(compgen -d -- "$cur") )
         return
         ;;
   esac

   # Complete option names.
   if [[ "$cur" == -* ]]; then
      COMPREPLY=( $(compgen -W '--config --fwdir --includedir' -- "$cur") )
      return
   fi

   # Bare positional: the firewall (host) name.
   _fw_tui_hosts "$cur"
}

complete -F _firewall_tui firewall-tui
complete -F _firewall_tui ./firewall-tui
