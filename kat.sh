#!/usr/bin/env bash
# Kat-Manager —— Kat 内核统一管理脚本（SS / AnyTLS / Trojan / SOCKS5）
#
#   bash kat.sh                      交互首页
#   bash kat.sh install ss           一键安装（其余用法：bash kat.sh help）
#   Development: curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash
#   Distribution: the generated release wrapper pins a commit (not main).
#
# A complete local checkout runs its own helpers. Otherwise (curl | bash,
# bash <(curl ...), a single downloaded script) kat_manager.py and
# kat_config.py are fetched from $KAT_MANAGER_BASE_URL and must match the
# SHA256 pinned below (scripts/pin-helpers.sh refreshes these two lines).
# A download/verification failure changes nothing.
set -Eeuo pipefail

KAT_MANAGER_VERSION="0.1.3"
# Filled with the full tagged commit ID only in a generated release wrapper.
KAT_HELPER_REF=""
KAT_HELPER_MANAGER_SHA256="8ba927986b53083bd9e3a5f5341dec8913bde0600a6d9c19297cd22b636d408f"
KAT_HELPER_CONFIG_SHA256="61f50695f7af774f5feec6b95fb1bdad46da0268a96b0ec1f74597d58fbbbeae"

kat_src="${BASH_SOURCE[0]:-}"
if [[ -z "$KAT_HELPER_REF" && -n "$kat_src" && -f "$kat_src" ]]; then
	kat_dir=$(cd -- "$(dirname -- "$kat_src")" && pwd)
	if [[ -f "$kat_dir/kat_manager.py" && -f "$kat_dir/kat_config.py" ]]; then
		exec python3 "$kat_dir/kat_manager.py" "$@"
	fi
fi
# Same error style as the helper: red ✖ only on a terminal without NO_COLOR.
kat_err() {
	if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then printf '\033[0;31m✖\033[0m %s\n' "$*" >&2; else printf '✖ %s\n' "$*" >&2; fi
}
for kat_tool in python3 curl sha256sum mktemp; do
	command -v "$kat_tool" >/dev/null 2>&1 || { kat_err "Kat-Manager 需要 $kat_tool；未做任何改动"; exit 1; }
done
if [[ -n "${KAT_MANAGER_BASE_URL:-}" ]]; then
	kat_base=${KAT_MANAGER_BASE_URL%/}
elif [[ $KAT_HELPER_REF =~ ^[0-9a-f]{40}$ ]]; then
	kat_base="https://raw.githubusercontent.com/shui1iao/Kat-Manager/$KAT_HELPER_REF"
elif [[ -z $KAT_HELPER_REF ]]; then
	kat_base='https://raw.githubusercontent.com/shui1iao/Kat-Manager/main'
else
	kat_err '无效的发布 helper 提交 ID；未做任何改动'
	exit 1
fi
kat_tmp=$(mktemp -d)
trap 'rm -rf "$kat_tmp"' EXIT
for kat_item in "kat_manager.py:$KAT_HELPER_MANAGER_SHA256" "kat_config.py:$KAT_HELPER_CONFIG_SHA256"; do
	kat_file=${kat_item%%:*}
	if ! curl -fsSL --retry 2 --connect-timeout 15 -o "$kat_tmp/$kat_file" -- "$kat_base/$kat_file"; then
		kat_err "下载 Kat-Manager 组件 $kat_file 失败；未做任何改动"
		exit 1
	fi
	if [[ "$(sha256sum "$kat_tmp/$kat_file" | cut -d' ' -f1)" != "${kat_item#*:}" ]]; then
		kat_err "Kat-Manager 组件 $kat_file 的 SHA256 与脚本内置值不符（脚本与仓库版本不一致？请重新获取 kat.sh）；未做任何改动"
		exit 1
	fi
done
# stdin may be the piped script itself: every prompt reads /dev/tty instead.
python3 "$kat_tmp/kat_manager.py" "$@" </dev/null
exit $?
