#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 save|compare|compare-lenient|list [baseline] [filter]" >&2
    exit 2
}

mode="${1:-}"
baseline="${2:-}"
filter="${3:-}"
criterion_args=()
if [[ -n "$filter" ]]; then
    criterion_args+=("$filter")
fi

case "$mode" in
    save)
        [[ -n "$baseline" ]] || usage
        cargo bench -p xparq --bench consensus -- "${criterion_args[@]}" --save-baseline "$baseline"
        ;;
    compare)
        [[ -n "$baseline" ]] || usage
        cargo bench -p xparq --bench consensus -- "${criterion_args[@]}" --baseline "$baseline"
        ;;
    compare-lenient)
        [[ -n "$baseline" ]] || usage
        cargo bench -p xparq --bench consensus -- "${criterion_args[@]}" --baseline-lenient "$baseline"
        ;;
    list)
        cargo bench -p xparq --bench consensus -- --list
        ;;
    *)
        usage
        ;;
esac
