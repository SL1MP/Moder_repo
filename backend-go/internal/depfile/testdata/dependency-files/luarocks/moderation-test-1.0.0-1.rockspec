package = "moderation-test"
version = "1.0.0-1"

source = {
  url = "https://example.invalid/moderation-test-1.0.0.tar.gz"
}

dependencies = {
  "lua == 5.4-1",
  "luasocket == 3.1.0-1"
}

build = {
  type = "builtin",
  modules = {}
}
