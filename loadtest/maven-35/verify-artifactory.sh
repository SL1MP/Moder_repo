#!/usr/bin/env bash
set -euo pipefail

: "${JFROG_URL:?Укажите JFROG_URL, например https://repo.example/artifactory}"
: "${JFROG_REPO:?Укажите JFROG_REPO с опубликованными Maven-пакетами}"
: "${JFROG_TOKEN:?Укажите JFROG_TOKEN}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REQUESTS_FILE="${1:-${SCRIPT_DIR}/requests.json}"
failures=0

allowed_re='(\.zip|\.jar|\.pom|\.aar|\.klib|\.module)$|^protoc-.*\.exe$'
forbidden_re='-sources\.jar$|-javadoc\.jar$|\.(md5|sha1|sha256|sha512|asc)$'

while IFS=$'\t' read -r name version; do
  group="${name%%:*}"
  artifact="${name#*:}"
  group_path="${group//./\/}"
  artifact_path="${group_path}/${artifact}/${version}"
  api_url="${JFROG_URL%/}/api/storage/${JFROG_REPO}/${artifact_path}?list&deep=0&listFolders=0"

  if ! response="$(curl --fail --silent --show-error \
      -H "Authorization: Bearer ${JFROG_TOKEN}" "$api_url")"; then
    printf 'FAIL %-72s каталог не найден\n' "${name}:${version}"
    failures=$((failures + 1))
    continue
  fi

  mapfile -t files < <(jq -r '.files[]?.uri | ltrimstr("/")' <<<"$response" | sort -u)
  if ((${#files[@]} == 0)); then
    printf 'FAIL %-72s нет файлов\n' "${name}:${version}"
    failures=$((failures + 1))
    continue
  fi

  bad=0
  for filename in "${files[@]}"; do
    if grep -Eiq "$forbidden_re" <<<"$filename"; then
      printf '  FORBIDDEN %s\n' "$filename"
      bad=1
    elif ! grep -Eiq "$allowed_re" <<<"$filename"; then
      printf '  UNEXPECTED %s\n' "$filename"
      bad=1
    fi
  done
  if ! printf '%s\n' "${files[@]}" | grep -Eiq '\.pom$'; then
    printf '  MISSING .pom\n'
    bad=1
  fi

  special=""
  case "$name" in
    org.jetbrains.kotlin:kotlin-gradle-plugin|org.jetbrains.kotlin:kotlin-serialization)
      count="$(printf '%s\n' "${files[@]}" | grep -Eic -- '-gradle[^/]*\.jar$' || true)"
      special="gradle-jars=${count}"
      ((count > 0)) || bad=1
      ;;
    androidx.appcompat:appcompat)
      count="$(printf '%s\n' "${files[@]}" | grep -Eic '\.aar$' || true)"
      special="aar=${count}"
      ((count > 0)) || bad=1
      ;;
    org.jetbrains.kotlinx:kotlinx-coroutines-core-iosarm64)
      count="$(printf '%s\n' "${files[@]}" | grep -Eic '\.klib$' || true)"
      special="klib=${count}"
      ((count > 0)) || bad=1
      ;;
    com.google.protobuf:protoc)
      count="$(printf '%s\n' "${files[@]}" | grep -Eic '^protoc-.*\.exe$' || true)"
      special="protoc-exe=${count}"
      ((count > 0)) || bad=1
      ;;
    org.apache.maven:apache-maven)
      count="$(printf '%s\n' "${files[@]}" | grep -Eic '\.zip$' || true)"
      special="zip=${count}"
      ((count > 0)) || bad=1
      ;;
  esac

  if ((bad)); then
    printf 'FAIL %-72s files=%d %s\n' "${name}:${version}" "${#files[@]}" "$special"
    failures=$((failures + 1))
  else
    printf 'PASS %-72s files=%d %s\n' "${name}:${version}" "${#files[@]}" "$special"
  fi
done < <(jq -r '.[] | [.name, .version] | @tsv' "$REQUESTS_FILE")

printf '\nИтог: failures=%d\n' "$failures"
exit "$((failures > 0))"
