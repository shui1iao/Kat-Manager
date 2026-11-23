#!/usr/bin/env bash
# Pin the SHA256 of kat_manager.py / kat_config.py inside kat.sh
# (KAT_HELPER_*_SHA256 lines). curl|bash mode downloads both helpers from the
# repository and refuses them unless they match these pinned values, so run
# this after every helper change and commit kat.sh together with the helpers:
#
#   bash scripts/pin-helpers.sh            # pin (repository root = parent of scripts/)
#   bash scripts/pin-helpers.sh DIR        # pin another checkout
#   bash scripts/pin-helpers.sh --check    # verify only, change nothing (exit 1 if stale)
#
#   bash scripts/pin-helpers.sh --release-wrapper vX.Y.Z OUTPUT
# Emit a *new* wrapper for an existing, explicitly selected version tag.
# Neither mode creates tags or publishes anything.
set -euo pipefail
if [[ "${1:-}" == --release-wrapper ]]; then
	[[ $# == 3 ]] || { echo 'usage: --release-wrapper vX.Y.Z NEW_OUTPUT' >&2; exit 2; }
	tag=$2
	case $3 in /*) output=$3 ;; *) output=$PWD/$3 ;; esac
	cd -- "$(dirname -- "$0")/.."
	[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $tag == "v$(cat version.txt)" ]] || { echo 'choose the tag for this version.txt' >&2; exit 1; }
	ref=$(git rev-parse --verify "refs/tags/$tag^{commit}")
	[[ $ref =~ ^[0-9a-f]{40}$ ]] || exit 1
	for path in kat.sh kat_manager.py kat_config.py version.txt scripts/pin-helpers.sh; do
		[[ $(git rev-parse "$ref:$path") == "$(git hash-object --no-filters "$path")" ]] || { echo "tag content differs: $path" >&2; exit 1; }
	done
	bash scripts/pin-helpers.sh --check
	[[ $(grep -cx 'KAT_HELPER_REF=""' kat.sh) == 1 && ! -e $output && ! -L $output ]] || { echo 'expected a development wrapper and a new output path' >&2; exit 1; }
	(set -C; sed "s/^KAT_HELPER_REF=\"\"$/KAT_HELPER_REF=\"$ref\"/" kat.sh > "$output")
	echo "prepared $output for $tag ($ref); nothing published"
	exit 0
fi
check=0
if [[ "${1:-}" == "--check" ]]; then
	check=1
	shift
fi
cd "${1:-$(dirname -- "$0")/..}"
[[ -f kat.sh && -f kat_manager.py && -f kat_config.py && -f version.txt ]] || { echo "kat.sh/kat_manager.py/kat_config.py/version.txt missing" >&2; exit 1; }
status=0
for pair in MANAGER:kat_manager.py CONFIG:kat_config.py; do
	name=${pair%%:*} file=${pair#*:}
	sum=$(sha256sum "$file" | cut -d' ' -f1)
	[[ $(grep -c "^KAT_HELPER_${name}_SHA256=\"[0-9a-f]\{64\}\"$" kat.sh) == 1 ]] || { echo "expected exactly one KAT_HELPER_${name}_SHA256 line in kat.sh" >&2; exit 1; }
	if ((check)); then
		if grep -q "^KAT_HELPER_${name}_SHA256=\"$sum\"$" kat.sh; then
			echo "ok $file sha256=$sum"
		else
			echo "STALE: kat.sh KAT_HELPER_${name}_SHA256 does not match $file ($sum); run scripts/pin-helpers.sh" >&2
			status=1
		fi
		continue
	fi
	sed -i -E "s/^(KAT_HELPER_${name}_SHA256=)\"[0-9a-f]{64}\"$/\\1\"$sum\"/" kat.sh
	grep -q "^KAT_HELPER_${name}_SHA256=\"$sum\"$" kat.sh || { echo "failed to pin $file" >&2; exit 1; }
	echo "pinned $file sha256=$sum"
done
# version.txt is the single version source for kat.sh and kat_manager.py.
version=$(tr -d '[:space:]' < version.txt)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version.txt must be X.Y.Z" >&2; exit 1; }
grep -q "^KAT_MANAGER_VERSION=\"$version\"$" kat.sh || { echo "kat.sh KAT_MANAGER_VERSION != version.txt ($version)" >&2; exit 1; }
grep -q "^VERSION = '$version'$" kat_manager.py || { echo "kat_manager.py VERSION != version.txt ($version)" >&2; exit 1; }
exit "$status"
