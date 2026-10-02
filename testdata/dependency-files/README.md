# Малые файлы для проверки загрузки зависимостей

Каждый каталог содержит один минимальный файл, который можно загрузить на
странице **Добавить пакеты → Файл зависимостей**, предварительно выбрав
соответствующий пакетный менеджер.

| Каталог | Менеджер | Файл | Ожидаемый пакет |
|---|---|---|---|
| `pypi` | PyPI | `requirements.txt` | `requests==2.31.0` |
| `npm` | npm | `package-lock.json` | `lodash@4.17.21` |
| `go` | Go modules | `go.mod` | `github.com/google/uuid@v1.6.0` |
| `nuget` | NuGet | `packages.config` | `Newtonsoft.Json@13.0.3` |
| `maven` | Maven | `pom.xml` | `org.apache.commons:commons-lang3:3.14.0` |
| `conan` | Conan | `conanfile.txt` | `zlib/1.3.1` |
| `docker` | Docker | `Dockerfile` | `postgres:14.23` по index digest |
| `luarocks` | LuaRocks | `moderation-test-1.0.0-1.rockspec` | `luasocket@3.1.0-1` |
| `terraform` | Terraform | `.terraform.lock.hcl` | `hashicorp/null@3.2.2` |
| `php` | Composer | `composer.json` | `psr/log:3.0.0` |

`git` и `files` сюда не входят: это способы модерации репозитория и
произвольного бинарного файла, а не пакетные менеджеры с dependency-файлом.

Файлы намеренно содержат по одной прямой зависимости, чтобы результат ручной
проверки был однозначным и не создавал большую очередь.

Кроме стандартного содержимого манифестов, сервис принимает сокращённый
построчный формат внутри файла с ожидаемым именем:

```text
# pom.xml
org.apache.commons:commons-lang3:3.14.0

# conanfile.txt
zlib/1.3.1

# любой *.rockspec
luasocket@3.1.0-1

# .terraform.lock.hcl
hashicorp/null@3.2.2
```
