#!/usr/bin/env bash
# 基于 sing-box 1.14.x 稳定版构建个人模板功能内核。
set -euo pipefail

usage() {
    cat <<'HELP'
用法: ./build.sh [linux-amd64|linux-arm64|android-arm64|all]
默认: all

产物和日志: sing-box/bin/
依赖、编译缓存和临时文件: sing-box/.cache/
环境变量: BUILD_PARALLELISM（默认 4）、BUILD_TAGS（可覆盖默认编译标签）
脚本使用现有 Go 工具链和已缓存依赖，不自动下载工具链或依赖。
HELP
}

if (( $# > 1 )); then
    usage >&2
    exit 2
fi
TARGET="${1:-all}"
case "${TARGET}" in
    help|-h|--help) usage; exit 0 ;;
    linux-amd64|linux-arm64|android-arm64|all) ;;
    *) echo "未知目标: ${TARGET}" >&2; usage >&2; exit 2 ;;
esac

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "${SCRIPT_DIR}"
command -v go >/dev/null || { echo "请先安装项目需要的 Go 工具链。" >&2; exit 1; }

# 使用最近的发布标签，拒绝预发布版本和其他版本系列。
BASE_TAG=$(git describe --tags --abbrev=0)
if [[ ! "${BASE_TAG}" =~ ^v1\.14\.[0-9]+$ ]]; then
    echo "构建基线必须是 1.14.x 稳定版；当前最近标签: ${BASE_TAG}" >&2
    exit 1
fi
BASE_VERSION="${BASE_TAG#v}"
COMMIT_COUNT=$(git rev-list --count "${BASE_TAG}..HEAD")
COMMIT_HASH=$(git rev-parse --short HEAD)
VERSION_TAG="${BASE_VERSION}-r${COMMIT_COUNT}-g${COMMIT_HASH}-template"
# 工作区存在未提交源码时，在版本中标记 dirty。
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    VERSION_TAG="${VERSION_TAG}-dirty"
fi

export GOPATH="${SCRIPT_DIR}/.cache/go"
export GOMODCACHE="${SCRIPT_DIR}/.cache/go-mod"
export GOCACHE="${SCRIPT_DIR}/.cache/go-build"
export GOTMPDIR="${SCRIPT_DIR}/.cache/tmp"
export TMPDIR="${GOTMPDIR}"
export GOTOOLCHAIN=local
export GOPROXY=off
mkdir -p "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}" "${GOTMPDIR}"
OUTPUT_DIR="${SCRIPT_DIR}/bin"
mkdir -p "${OUTPUT_DIR}"

BUILD_PARALLELISM="${BUILD_PARALLELISM:-4}"
if [[ ! "${BUILD_PARALLELISM}" =~ ^[1-9][0-9]*$ ]]; then
    echo "BUILD_PARALLELISM 必须是正整数。" >&2
    exit 2
fi
BUILD_TAGS="${BUILD_TAGS:-with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_tailscale,badlinkname,tfogo_checklinkname0}"
LDFLAGS="-checklinkname=0 -s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=${VERSION_TAG}"

echo "构建版本: ${VERSION_TAG}"
echo "Go 工具链: $(go version)"
echo "编译标签: ${BUILD_TAGS}"

build_target() {
    local name="$1" goos="$2" goarch="$3"
    local output_path="${OUTPUT_DIR}/sing-box-${name}"
    local temporary_output="${output_path}.tmp"
    local build_log="${OUTPUT_DIR}/build-${name}.log"
    local started=${SECONDS}
    echo "正在编译 ${name} ..."
    # 先写入临时文件，编译成功后才替换现有内核。
    if env CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build \
        -mod=readonly -p "${BUILD_PARALLELISM}" -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" -trimpath \
        -o "${temporary_output}" ./cmd/sing-box >"${build_log}" 2>&1; then
        mv -f -- "${temporary_output}" "${output_path}"
        echo "成功: ${output_path}（$((SECONDS - started)) 秒）"
    else
        echo "编译失败，日志: ${build_log}" >&2
        tail -n 40 -- "${build_log}" >&2
        return 1
    fi
}

case "${TARGET}" in
    linux-amd64) build_target linux-amd64 linux amd64 ;;
    linux-arm64) build_target linux-arm64 linux arm64 ;;
    android-arm64) build_target android-arm64 android arm64 ;;
    all)
        build_target linux-amd64 linux amd64
        build_target linux-arm64 linux arm64
        build_target android-arm64 android arm64
        ;;
esac
