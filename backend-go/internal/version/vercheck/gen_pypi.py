import json, os, pathlib, urllib.request
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion

# Куда класть корпус: по умолчанию рядом со скриптом.
OUT = pathlib.Path(os.environ.get("VERCHECK_OUT", "."))

PKGS = ["requests","urllib3","flask","django","numpy","pandas","boto3","click","jinja2",
        "sqlalchemy","pydantic","fastapi","attrs","cryptography","pytest","setuptools",
        "aiohttp","celery","redis","werkzeug"]

def get(url, accept=None):
    req = urllib.request.Request(url, headers={"Accept": accept} if accept else {})
    return json.load(urllib.request.urlopen(req, timeout=30))

specs = set()
for name in PKGS:
    try:
        d = get(f"https://pypi.org/pypi/{name}/json")
    except Exception as e:
        print("skip", name, e); continue
    for rd in (d["info"].get("requires_dist") or []):
        try:
            r = Requirement(rd)
        except Exception:
            continue
        if str(r.specifier):
            specs.add(str(r.specifier))

versions = set()
for name in ["urllib3", "numpy", "django", "pytest"]:
    d = get(f"https://pypi.org/simple/{name}/", "application/vnd.pypi.simple.v1+json")
    versions.update(d["versions"])
versions = sorted(versions)[:400]

cases = []
for spec in sorted(specs):
    try:
        ss = SpecifierSet(spec)
    except InvalidSpecifier:
        continue
    for v in versions:
        try:
            Version(v)
        except InvalidVersion:
            continue
        cases.append({"spec": spec, "version": v, "expected": ss.contains(v, prereleases=True)})

json.dump(cases, open(OUT / "pypi_cases.json", "w"))
print("specs:", len(specs), "versions:", len(versions), "cases:", len(cases))
