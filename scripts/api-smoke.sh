#!/usr/bin/env bash
# Прогон REST API сервиса модерации: заведение пакета, проверка по базе, статусы,
# очереди, уведомления, права ролей. Ничего не удаляет — только читает и создаёт заявку.
#
#   ./scripts/api-smoke.sh [пакет]
#
# Токен (в порядке приоритета):
#   1) TOKEN=eyJ...                    — готовый Bearer-токен
#   2) SVC_USER=... SVC_PASSWORD=...   — сервисная учётка (нужен LOCAL_AUTH_ENABLED=true)
# Для шагов роли DevSecOps: SEC_TOKEN или SEC_USER/SEC_PASSWORD.
#
# Переменные: BASE (http://localhost:8080), MANAGER (pypi), TIMEOUT (120).
#
# Python-вставки лежат в переменных с одинарными кавычками: внутри свободно
# используются двойные, экранировать ничего не нужно. Значения полей сначала
# кладём в локальные переменные — так f-строки работают и на Python < 3.12,
# где вложенные одинаковые кавычки в f-строке недопустимы.
set -uo pipefail

BASE="${BASE:-http://localhost:8080}"
API="$BASE/api/v1"
PKG="${1:-six==1.16.0}"
MANAGER="${MANAGER:-pypi}"
TIMEOUT="${TIMEOUT:-120}"

head_() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
ok_()   { printf '\033[0;32m%s\033[0m\n' "$1"; }
err_()  { printf '\033[0;31m%s\033[0m\n' "$1"; }

# ------------------------------------------------------------------ python-хелперы
PY_SHOW='
import json, sys
raw = sys.stdin.read()
limit = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
try:
    print(json.dumps(json.loads(raw), ensure_ascii=False, indent=2)[:limit])
except Exception:
    print("НЕ JSON:", raw[:500])
'

PY_PICK='
import json, sys
data = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    if not key:
        continue
    data = data[int(key)] if key.isdigit() else (data or {}).get(key)
    if data is None:
        break
print("" if data is None else data)
'

PY_MANAGERS='
import json, sys
for m in json.load(sys.stdin):
    code = m["code"]
    fmt = m["entry_format"]
    files = ", ".join(m["dependency_files"])
    print(f"  {code:6} {fmt:26} файлы: {files}")
'

PY_CREATED='
import json, sys
d = json.load(sys.stdin)
rid, status = d["request_id"], d["status"]
accepted, in_base, invalid = d["accepted"], d["skipped_already_in_base"], d["invalid"]
print(f"  заявка #{rid}, статус {status}")
print(f"  принято к проверке: {accepted}, уже в базе: {in_base}, ошибок формата: {invalid}")
for w in d.get("warnings") or []:
    print("  предупреждение:", w)
for p in d["packages"]:
    state = p["state"]
    name = p.get("name") or p["raw"]
    version = p.get("version") or ""
    print(f"  {state:16} {name} {version}".rstrip())
    if p.get("message"):
        print("       ", p["message"])
    if p.get("install_command"):
        print("        установка:", p["install_command"])
    if p.get("expected_format"):
        print("        ожидается:", p["expected_format"])
'

PY_FINAL='
import json, sys
d = json.load(sys.stdin)
rid, title, approved = d["request_id"], d["status_title"], d["approved"]
print(f"  заявка #{rid}: {title} (approved={approved})")
for p in d["packages"]:
    name, version, st = p["name"], p["version"], p["status_title"]
    print()
    print(f"  {name} {version} -> {st}")
    if p.get("blocked_reason"):
        print("    причина:", p["blocked_reason"])
    if p.get("next_action"):
        print("    что делать:", p["next_action"])
    if p.get("install_command"):
        print("    установка:", p["install_command"])
    for v in p.get("vulnerabilities") or []:
        vid, score, fixed = v["id"], v["score"], v.get("fixed_versions")
        print(f"    CVE {vid} балл {score}, исправлено в {fixed}")
    print("    шаги конвейера:")
    for s in p.get("steps") or []:
        order, title_, result = s["order"], s["title"], s["result"]
        msg = (s.get("message") or "")[:88]
        print(f"      {order} {title_:28} {result:8} {msg}")
'

PY_SEARCH='
import json, sys
d = json.load(sys.stdin)
print("  найдено:", d["total"])
for i in d["items"]:
    mgr, name, version, st = i["manager"], i["name"], i["version"], i["status"]
    lic = i.get("license_spdx") or "—"
    print(f"  {mgr:6} {name:24} {version:12} {st:12} {lic}")
    if i.get("install_command"):
        print("         ", i["install_command"])
'

PY_REQUESTS='
import json, sys
for r in json.load(sys.stdin):
    rid, mgr, title = r["request_id"], r["manager"], r["status_title"]
    total, approved = r["total"], r["approved"]
    print(f"  #{rid:<5} {mgr:6} {title:24} пакетов {total}, одобрено {approved}")
'

PY_NOTIFY='
import json, sys
d = json.load(sys.stdin)
print("  непрочитанных:", d["unread"])
for n in d["items"][:5]:
    when, title = n["created_at"][:19], n["title"]
    print(f"  {when}  {title}")
'

PY_SETTINGS='
import json, sys
keep = {"QUARANTINE_DAYS", "VULN_MAX_SCORE", "OSV_SOURCE", "ARTIFACT_STORE",
        "ARTIFACT_BASE_URL", "S3_BUCKET", "LOCAL_AUTH_ENABLED"}
for row in json.load(sys.stdin):
    if row["env"] in keep:
        env, value = row["env"], row["value"]
        print(f"  {env:24} = {value}")
'

PY_POLICIES='
import json, sys
d = json.load(sys.stdin)
print("  правил blacklist:", len(d["blacklist"]["rules"]))
print("  разрешённых лицензий:", len(d["licenses"]["allowed"]))
v = d["vuln_index"]
src, ver, stale = v["source"], v["version"], v["stale"]
print(f"  OSV: источник={src} версия={ver} устарела={stale}")
'

PY_CHECK='
import json, sys
for row in json.load(sys.stdin)["packages"]:
    raw, state = row["raw"], row["state"]
    print(f"  {raw:28} {state}")
    if row.get("message"):
        print("       ", row["message"])
    if row.get("install_command"):
        print("        установка:", row["install_command"])
    if row.get("expected_format"):
        print("        ожидается:", row["expected_format"])
'

PY_QUEUE='
import json, sys
rows = json.load(sys.stdin)
if isinstance(rows, dict):
    print("  ", (rows.get("error") or {}).get("message"))
    raise SystemExit
print("  в очереди:", len(rows))
for r in rows:
    iid, name, version = r["item_id"], r["name"], r["version"]
    title, waiting = r["status_title"], r.get("waiting_hours")
    print(f"  item #{iid} {name} {version} — {title}, ждёт {waiting} ч")
    if r.get("blocked_reason"):
        print("       ", r["blocked_reason"][:110])
ids = [str(r["item_id"]) for r in rows]
if ids:
    print()
    print("  ID пакетов для решения:", " ".join(ids))
'

show()  { python3 -c "$PY_SHOW" "${1:-4000}"; }
pick()  { python3 -c "$PY_PICK" "$1"; }
req()   { local m="$1" p="$2"; shift 2; curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $TOKEN" "$@"; }
login() { curl -sS -X POST "$API/auth/token" -H 'Content-Type: application/json' \
            -d "{\"username\":\"$1\",\"password\":\"$2\"}" | pick access_token; }

# ------------------------------------------------------------------ токен
if [ -z "${TOKEN:-}" ] && [ -n "${SVC_USER:-}" ] && [ -n "${SVC_PASSWORD:-}" ]; then
  TOKEN="$(login "$SVC_USER" "$SVC_PASSWORD")"
fi
if [ -z "${TOKEN:-}" ]; then
  err_ "Нет токена."
  cat >&2 <<'EOF'
Варианты:
  1) Сервисная учётка (в .env: LOCAL_AUTH_ENABLED=true, затем make restart):
       docker compose exec api python -m app.cli create-service-account ci-bot \
         --roles developer --password secret
       SVC_USER=ci-bot SVC_PASSWORD=secret ./scripts/api-smoke.sh
  2) Токен из браузера: F12 -> Application -> Session Storage -> moderation.session
       TOKEN=eyJ... ./scripts/api-smoke.sh
EOF
  exit 1
fi

# ------------------------------------------------------------------ прогон
head_ "0. Живость сервиса"
curl -sS "$BASE/health" | show 600

head_ "1. Кто я и какие роли"
req GET /auth/me | show 800

head_ "2. Менеджеры и форматы записей"
req GET /managers | python3 -c "$PY_MANAGERS"

head_ "3. Проверка по базе: можно ли уже ставить (без создания заявки)"
req POST /packages/check -H 'Content-Type: application/json' \
  -d "{\"manager\":\"$MANAGER\",\"packages\":[\"$PKG\",\"nosuchpkg==9.9.9\",\"broken\"]}" \
  | python3 -c "$PY_CHECK"

head_ "4. Заводим заявку: $PKG"
IDEM="smoke-$(date +%s)"
CREATED="$(req POST /requests -H 'Content-Type: application/json' -H "Idempotency-Key: $IDEM" \
  -d "{\"manager\":\"$MANAGER\",\"packages\":[\"$PKG\"],\"reason\":\"проверка API\"}")"
echo "$CREATED" | python3 -c "$PY_CREATED"
RID="$(echo "$CREATED" | pick request_id)"
[ -n "$RID" ] || { err_ "Заявка не создана:"; echo "$CREATED" | show 1500; exit 1; }

head_ "5. Идемпотентность: повтор с тем же Idempotency-Key"
req POST /requests -H 'Content-Type: application/json' -H "Idempotency-Key: $IDEM" \
  -d "{\"manager\":\"$MANAGER\",\"packages\":[\"$PKG\"],\"reason\":\"проверка API\"}" \
  | python3 -c "$PY_CREATED"
echo "  (номер заявки должен совпадать с $RID)"

head_ "6. Финальный статус — блокирующий вариант для CI (wait=true)"
FINAL="$(req GET "/requests/$RID?wait=true&timeout=$TIMEOUT")"
echo "$FINAL" | python3 -c "$PY_FINAL"
APPROVED="$(echo "$FINAL" | pick approved)"

head_ "7. Ошибка формата записи: пометка invalid_format с ожидаемым форматом"
req POST /requests -H 'Content-Type: application/json' \
  -d "{\"manager\":\"$MANAGER\",\"packages\":[\"lodash@4.17.21\"],\"reason\":\"неверный формат\"}" \
  | python3 -c "$PY_CREATED"

head_ "8. Неизвестный менеджер: машинный код ошибки"
req POST /requests -H 'Content-Type: application/json' \
  -d '{"manager":"cargo","packages":["serde==1.0.0"]}' | show 700

head_ "9. База пакетов: поиск"
NAME="$(printf '%s' "$PKG" | cut -d= -f1 | cut -d@ -f1)"
req GET "/packages?q=$NAME&limit=10" | python3 -c "$PY_SEARCH"

head_ "10. Мои заявки"
req GET "/requests?mine=true&limit=5" | python3 -c "$PY_REQUESTS"

head_ "11. Уведомления"
req GET /notifications | python3 -c "$PY_NOTIFY"

head_ "12. Настройки (только чтение, с именами переменных)"
req GET /settings | python3 -c "$PY_SETTINGS"

head_ "13. Политики и состояние базы OSV"
req GET /settings/policies | python3 -c "$PY_POLICIES"

head_ "14. Права: разработчику очередь DevSecOps недоступна (ожидаем 403)"
req GET /queue/security | show 400

if [ -z "${SEC_TOKEN:-}" ] && [ -n "${SEC_USER:-}" ] && [ -n "${SEC_PASSWORD:-}" ]; then
  SEC_TOKEN="$(login "$SEC_USER" "$SEC_PASSWORD")"
fi

head_ "15. Очередь DevSecOps"
if [ -n "${SEC_TOKEN:-}" ]; then
  curl -sS "$API/queue/security" -H "Authorization: Bearer $SEC_TOKEN" | python3 -c "$PY_QUEUE"
  cat <<EOF

  Разрешить публикацию (подставьте ITEM_ID из списка выше):
    curl -sS -X POST $API/items/ITEM_ID/security-decision \\
      -H "Authorization: Bearer \$SEC_TOKEN" -H 'Content-Type: application/json' \\
      -d '{"approve":true,"comment":"риск принят"}'

  Снять карантин досрочно:
    curl -sS -X POST $API/items/ITEM_ID/quarantine/release \\
      -H "Authorization: Bearer \$SEC_TOKEN" -H 'Content-Type: application/json' \\
      -d '{"comment":"проверено вручную"}'
EOF
else
  echo "  пропущено: задайте SEC_TOKEN или SEC_USER/SEC_PASSWORD"
fi

head_ "ИТОГ"
case "$APPROVED" in
  True|true)
    ok_ "Заявка #$RID одобрена — пакет опубликован в артефактори."
    echo "Проверить в хранилище:"
    echo "  curl -sS -u admin:admin123 'http://localhost:8082/service/rest/v1/search?repository=pypi-internal'"
    ;;
  *)
    echo "Заявка #$RID не одобрена автоматически."
    echo "В шаге 6 выше видно, на каком шаге конвейер остановился и что делать дальше."
    echo "Карточка в UI: $BASE/requests/$RID"
    ;;
esac
