import json, os, pathlib, urllib.request
from packaging.version import Version, InvalidVersion

# Куда класть корпус: по умолчанию рядом со скриптом.
OUT = pathlib.Path(os.environ.get("VERCHECK_OUT", "."))

versions = set()
for name in ["urllib3", "numpy", "django", "pytest", "setuptools", "boto3", "cryptography"]:
    req = urllib.request.Request(f"https://pypi.org/simple/{name}/",
                                 headers={"Accept": "application/vnd.pypi.simple.v1+json"})
    versions.update(json.load(urllib.request.urlopen(req, timeout=30))["versions"])

good = []
for v in versions:
    try:
        good.append((Version(v), v))
    except InvalidVersion:
        pass
good.sort()
pairs = []
for i in range(0, len(good) - 1):
    a, b = good[i], good[i + 1]
    want = -1 if a[0] < b[0] else (0 if a[0] == b[0] else 1)
    pairs.append({"a": a[1], "b": b[1], "want": want})
    if i + 50 < len(good):
        c = good[i + 50]
        want2 = -1 if a[0] < c[0] else (0 if a[0] == c[0] else 1)
        pairs.append({"a": a[1], "b": c[1], "want": want2})
json.dump(pairs, open(OUT / "pypi_compare.json", "w"))
print("versions:", len(good), "pairs:", len(pairs))
