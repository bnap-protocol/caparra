#!/bin/sh
# leak-guard: refuse to publish private identifiers, home-directory paths or
# secrets from this repository.
#
# Usage:
#   ops/leak-guard.sh
#       Scan every tracked file in the working tree.
#   ops/leak-guard.sh --pre-push [REMOTE [URL]]  < ref-lines
#       Pre-push mode (this is how .githooks/pre-push calls it). Scans the
#       tracked files, then every commit being pushed: the lines each commit
#       adds (file names included), its author and committer names and
#       emails, and its message. Ref lines on stdin use the git pre-push
#       format: <local ref> <local sha> <remote ref> <remote sha>
#
# Exit status: 0 when clean, 1 when something was found, 2 on usage error.
#
# Checks:
#   identifiers  private names (case-insensitive), everywhere
#   home path    absolute macOS home-directory paths, everywhere
#   secrets      private key blocks, nsec keys, GitHub and API tokens,
#                extended private keys and Lightning invoices; skipped for
#                files under any vectors/ or fixtures/ directory, where test
#                material lives. Secret values are never printed.
#
# The forbidden strings below are assembled from fragments at runtime so that
# this file never matches its own scan. Keep it that way when adding entries.
# POSIX sh; needs git and grep plus sed, sort, tr and cut from the base system.

set -u

IDENTIFIERS='bondi''goo|pend''post|noma''dik|dominic''frei''90'
HOMEPATH='/Use''rs/'
SECRETS='-----BEGIN .*PRI''VATE KEY|nsec1[0-9a-z]{20,}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xprv[1-9A-HJ-NP-Za-km-z]{20,}|lnbc[0-9]+[a-z0-9]{50,}'

# Pathspecs that exempt test material from the secret scan only.
EX_VECTORS=':(exclude,glob)**/vectors/**'
EX_FIXTURES=':(exclude,glob)**/fixtures/**'

NL='
'
findings=0
commits_scanned=0

say() { printf '%s\n' "$*" >&2; }

flag() {
	# $1 = where, $2 = what
	findings=$((findings + 1))
	say "  [x] $1: $2"
}

# Join the unique case-folded matches of $IDENTIFIERS in stdin with spaces.
words_in() {
	grep -o -i -E -e "$IDENTIFIERS" | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

nonzero_sha() {
	case ${1:-0} in *[!0]*) return 0 ;; *) return 1 ;; esac
}

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
	say 'leak-guard: not inside a git working tree'
	exit 2
}
cd "$top" || exit 2

# ---------------------------------------------------------------- tracked files

scan_tracked() {
	# File names of tracked files.
	hits=$(git ls-files | grep -i -E -e "$IDENTIFIERS")
	if [ -n "$hits" ]; then
		while IFS= read -r h; do
			flag "$h" "identifier in file name: $(printf '%s\n' "$h" | words_in)"
		done <<EOF
$hits
EOF
	fi

	# Identifiers: "path:line:match".
	hits=$(git grep -n -o -I -i -E -e "$IDENTIFIERS" -- . 2>/dev/null)
	if [ -n "$hits" ]; then
		while IFS= read -r h; do
			flag "${h%:*}" "identifier \"${h##*:}\""
		done <<EOF
$hits
EOF
	fi

	# Home path: report "path:line" only.
	hits=$(git grep -n -I -F -e "$HOMEPATH" -- . 2>/dev/null | cut -d: -f1,2)
	if [ -n "$hits" ]; then
		while IFS= read -r h; do
			flag "$h" 'absolute home-directory path'
		done <<EOF
$hits
EOF
	fi

	# Secrets: "path:line" only, never the value.
	hits=$(git grep -n -I -E -e "$SECRETS" -- . "$EX_VECTORS" "$EX_FIXTURES" 2>/dev/null | cut -d: -f1,2)
	if [ -n "$hits" ]; then
		while IFS= read -r h; do
			flag "$h" 'secret-like string (value not shown)'
		done <<EOF
$hits
EOF
	fi
}

# ---------------------------------------------------------------- commits

EMPTY_TREE=$(git hash-object -t tree /dev/null)

# Print the lines a commit adds, each as "path: +text", plus one "path: +"
# line per added, copied, modified or renamed file so that file names are
# scanned even when the file is empty. Merge commits are compared with their
# first parent, root commits with the empty tree. Extra arguments are
# pathspecs.
added_lines() {
	c=$1
	shift
	if git rev-parse -q --verify "$c^1" >/dev/null 2>&1; then
		base="$c^1"
	else
		base=$EMPTY_TREE
	fi
	git diff --name-only --diff-filter=ACMR "$base" "$c" -- "$@" 2>/dev/null |
		sed 's/$/: +/'
	git diff --no-color --no-ext-diff --no-textconv -U0 \
		--src-prefix=a/ --dst-prefix=b/ "$base" "$c" -- "$@" 2>/dev/null |
		sed -n -e '/^+++ b\//{s/^+++ b\///;h;d;}' \
			-e '/^+/{G;s/^\(.*\)\n\(.*\)$/\2: \1/;p;}'
}

# Flag each distinct file in "path: +text" hit lines ($1) for commit $2.
flag_files() {
	files=$(printf '%s\n' "$1" | sed 's/: +.*$//' | sort -u)
	while IFS= read -r f; do
		flag "$2 $f" "$3"
	done <<EOF
$files
EOF
}

scan_commit() {
	c=$1
	where="commit $(git rev-parse --short "$c")"
	commits_scanned=$((commits_scanned + 1))

	# Author, committer and message.
	meta=$(git log -1 --format='%an <%ae>%n%cn <%ce>%n%B' "$c")
	if printf '%s\n' "$meta" | grep -q -i -E -e "$IDENTIFIERS"; then
		flag "$where" "identifier in author, committer or message: $(printf '%s\n' "$meta" | words_in)"
	fi
	if printf '%s\n' "$meta" | grep -q -F -e "$HOMEPATH"; then
		flag "$where" 'absolute home-directory path in author, committer or message'
	fi
	if printf '%s\n' "$meta" | grep -q -E -e "$SECRETS"; then
		flag "$where" 'secret-like string in author, committer or message (value not shown)'
	fi

	# Added lines. The "path: " prefix puts file names into the scan too.
	lines=$(added_lines "$c" .)
	hits=$(printf '%s\n' "$lines" | grep -i -E -e "$IDENTIFIERS")
	if [ -n "$hits" ]; then
		flag_files "$hits" "$where" "adds identifier text: $(printf '%s\n' "$hits" | words_in)"
	fi
	hits=$(printf '%s\n' "$lines" | grep -F -e "$HOMEPATH")
	if [ -n "$hits" ]; then
		flag_files "$hits" "$where" 'adds an absolute home-directory path'
	fi
	hits=$(added_lines "$c" . "$EX_VECTORS" "$EX_FIXTURES" | grep -E -e "$SECRETS")
	if [ -n "$hits" ]; then
		flag_files "$hits" "$where" 'adds a secret-like string (value not shown)'
	fi
}

scan_pushed() {
	remote=$1
	refs=$2
	revs=''
	while read -r lref lsha rref rsha; do
		: "${lref:-}" "${rref:-}"
		nonzero_sha "${lsha:-}" || continue # empty line or branch deletion
		if nonzero_sha "${rsha:-}" && git cat-file -e "$rsha^{commit}" 2>/dev/null; then
			more=$(git rev-list "$rsha..$lsha")
		else
			# New branch, or the remote tip is unknown here: everything the
			# remote-tracking refs do not already contain.
			more=$(git rev-list "$lsha" --not --remotes="$remote")
		fi
		revs="$revs$NL$more"
	done <<EOF
$refs
EOF
	revs=$(printf '%s\n' "$revs" | grep . | sort -u)
	[ -n "$revs" ] || return 0
	while IFS= read -r c; do
		scan_commit "$c"
	done <<EOF
$revs
EOF
}

# ---------------------------------------------------------------- main

mode=tracked
case ${1:-} in
'') ;;
--pre-push)
	mode=pre-push
	shift
	;;
-h | --help)
	sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
*)
	say "leak-guard: unknown argument: $1 (try --help)"
	exit 2
	;;
esac

say 'leak-guard: scanning tracked files'
scan_tracked
if [ "$mode" = pre-push ]; then
	remote=${1:-origin}
	refs=$(cat)
	say "leak-guard: scanning commits being pushed to $remote"
	scan_pushed "$remote" "$refs"
fi

if [ "$findings" -gt 0 ]; then
	say ''
	say "leak-guard: FAILED with $findings finding(s)."
	say 'Remove the text above (rewrite the commits if it is in history) and try again.'
	exit 1
fi

if [ "$mode" = pre-push ]; then
	printf 'leak-guard: clean (%s tracked files, %s pushed commit(s))\n' \
		"$(git ls-files | grep -c .)" "$commits_scanned"
else
	printf 'leak-guard: clean (%s tracked files)\n' "$(git ls-files | grep -c .)"
fi
exit 0
