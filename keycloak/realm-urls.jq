# Добавляет внешний адрес сервиса в клиент moderation-web.
# Адреса localhost сохраняются: локальная разработка должна продолжать работать.
# Программа вынесена в отдельный файл, а не записана внутри RUN: Docker
# завершает инструкцию на переносе строки, и многострочный аргумент в Dockerfile
# пришлось бы экранировать построчно.
(.clients[] | select(.clientId == "moderation-web")) |= (
    .redirectUris = ([$url + "/*"] + .redirectUris | unique)
  | .webOrigins   = ([$url] + .webOrigins | unique)
  | .attributes["post.logout.redirect.uris"] =
      ([$url + "/*"] + (.attributes["post.logout.redirect.uris"] | split("##"))
       | unique | join("##"))
)
