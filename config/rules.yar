/*
 * Правила YARA для шага «Политические баннеры» (протестварь).
 *
 * Тот же файл используется в CI-конвейерах модерации, поэтому вердикт сервиса
 * и CI не расходится. Обновляется вместе с ними: правила пишет PT ESC.
 *
 * Путь внутри контейнера задаётся BANNER_RULES_FILE (по умолчанию
 * /config/rules.yar). После правки достаточно перезапустить api и worker —
 * правила компилируются при первом обращении.
 */

import "hash"

rule protestware__evolution__background: media {
  meta:
    reference = "https://github.com/evolution-cms/evolution/blob/1c586bc76f739264dcf0482530945875fa444b77/manager/media/style/default/images/login/default/login-background.jpg"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "01.03.2022"
  condition:
    hash.sha256(0, filesize) == "a04306c12a58fe4cfec3b812b5a0274a1d446f8c03a10be25d50512003cd3665"
}

rule protestware__sweetalert2__1: js {
  meta:
    reference = "https://github.com/sweetalert2/sweetalert2/pull/2428/commits/86d5af1686a5270a593f14ec90c6943884447824"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "22.04.2022"
  strings:
    $s1 = "noWarMessageForRussians" nocase
    $s2 = "no-war message for Russians" nocase
    $s3 = "corrupted by propaganda" nocase
    $s8 = "спецопераци" nocase
    $s9 = "brainwashed by propaganda" nocase
    $s11 = "annexation of Crimea" nocase

    $cond1 = "navigator.language === 'ru'"
    $cond2 = "location.host.match(/\\.(ru|su|xn--p1ai)$/)"
  condition:
    any of ($s*) or all of ($cond*)
}

rule protestware__sweetalert2__2: js {
  meta:
    reference = "https://github.com/sweetalert2/sweetalert2/pull/2462/commits/31716c6fe72b9afd13ec935be60d0b425738aa7c"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "05.07.2022"
  strings:
    $s3 = "leave-russia-now-and-apply-your-skills-to-the-world" nocase
    $s5 = "Путинский режим" nocase
    $s8 = "Нет войне" nocase

    $cond1 = "/^ru\\b/.test(navigator.language)"
    $cond2 = "location.host.match(/\\.(ru|su|xn--p1ai)$/)"
  condition:
    any of ($s*) or all of ($cond*)
}

rule protestware__terraform_aws_eks_banner_2_direct_svg: svg {
  meta:
    reference = "https://github.com/terraform-aws-modules/terraform-aws-eks/commit/fad350d5bf36a7e39aa3840926b4c9968e9f594c"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "12.03.2022"
  strings:
    $s1 = "stand-with-ukraine.pp.ua" nocase
    $s2 = "StandWithUkraine" nocase
    $s3 = "vshymanskyy" nocase

  condition:
    any of ($s*)
}

rule protestware__terraform_aws_eks: md {
  meta:
    reference = "https://github.com/terraform-aws-modules/terraform-aws-eks/commit/fad350d5bf36a7e39aa3840926b4c9968e9f594c"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "12.03.2022"
  strings:
    $s1 = "putin_khuylo" nocase
    $s2 = "Ukrainian sovereignty" nocase
    $s3 = "annexed Crimea" nocase
    $s4 = "war in Donbas" nocase
    $s5 = "Russian_invasion" nocase
    $s6 = "путин хуйло" nocase
    $s7 = "putin khuylo" nocase
    $s8 = "путин_хуйло" nocase

  condition:
    any of ($s*)
}

rule protestware__voicy: ts {
  meta:
    reference = "https://github.com/backmeupplz/voicy/commit/1da565a80ab8f2681fddbcf443df60e6a7a15fa5"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "02.03.2022"
  strings:
    $s1 = "Путин и его свита" nocase
    $s3 = "stopputin" nocase
    $s4 = "Putin and his cronies" nocase

  condition:
    any of ($s*)
}

rule protestware__EventSource: js {
  meta:
    reference = "https://github.com/Yaffle/EventSource/commit/de137927e13d8afac153d2485152ccec48948a7a"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "17.03.2022"
  strings:
        $tz1  = "Asia/Anadyr"
        $tz2  = "Asia/Barnaul"
        $tz3  = "Asia/Chita"
        $tz4  = "Asia/Irkutsk"
        $tz5  = "Asia/Kamchatka"
        $tz6  = "Asia/Khandyga"
        $tz7  = "Asia/Krasnoyarsk"
        $tz8  = "Asia/Magadan"
        $tz9  = "Asia/Novokuznetsk"
        $tz10 = "Asia/Novosibirsk"
        $tz11 = "Asia/Omsk"
        $tz12 = "Asia/Sakhalin"
        $tz13 = "Asia/Srednekolymsk"
        $tz14 = "Asia/Tomsk"
        $tz15 = "Asia/Ust-Nera"
        $tz16 = "Asia/Vladivostok"
        $tz17 = "Asia/Yakutsk"
        $tz18 = "Asia/Yekaterinburg"
        $tz19 = "Europe/Astrakhan"
        $tz20 = "Europe/Kaliningrad"
        $tz21 = "Europe/Kirov"
        $tz22 = "Europe/Moscow"
        $tz23 = "Europe/Samara"
        $tz24 = "Europe/Saratov"
        $tz25 = "Europe/Simferopol"
        $tz26 = "Europe/Ulyanovsk"
        $tz27 = "Europe/Volgograd"
        $tz28 = "W-SU"

        $code_check = "indexOf(new Intl.DateTimeFormat().resolvedOptions().timeZone) === -1"

        $s2 = "Россия напала" nocase
        $s3 = "Народ Украины" nocase
        $s4 = "защищать свою страну" nocase
        $s6 = "нападение России" nocase
        $s8 = "против России" nocase
        $s10 = "преступника Путина" nocase
        $s11 = "NetVoyne" nocase

    condition:
        (all of ($tz*) and $code_check) or (any of ($s*))
}

rule protestware__es5_ext: js {
  meta:
    reference = "https://github.com/medikoo/es5-ext/commit/28de285ed433b45113f01e4ce7c74e9a356b2af2"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "07.03.2022"
  strings:
        $tz1  = "Europe/Moscow"
        $tz2  = "Asia/Yakutsk"
        $tz3  = "Asia/Krasnoyarsk"
        $tz4  = "Europe/Samara"
        $tz5  = "Asia/Yekaterinburg" 
        $tz6  = "Asia/Irkutsk" 
        $tz7  = "Asia/Anadyr" 
        $tz8  = "Asia/Kamchatka" 
        $tz9  = "Europe/Kaliningrad" 
        $tz10 = "Asia/Vladivostok" 
        $tz11 = "Asia/Magadan"
        $tz12 = "Asia/Novosibirsk" 
        $tz13 = "Asia/Omsk"

        $code_check = "indexOf(new Intl.DateTimeFormat().resolvedOptions().timeZone) === -1"

        $s3 = "российских войск" nocase
        $s5 = "русских военных" nocase
        $s6 = "убитых гражданах" nocase
        $s7 = "защищать свою страну" nocase
        $s8 = "Владимира Зеленского" nocase
        $s9 = "нападение России" nocase
        $s11 = "против России" nocase
        $s12 = "ВВП России" nocase
        $s13 = "Остановите Путина" nocase
        $s14 = "Не позволяйте ФСБ" nocase

    condition:
        (all of ($tz*) and $code_check) or (any of ($s*))
}

rule protestware__Tasmota: ino {
  meta:
    reference = "https://github.com/arendst/Tasmota/commit/98cbf2587a1a914bbd16996ebb48dd451d3da448"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "01.03.2022"
  strings:
        $s2 = "Free Ukrain" nocase
        $s4 = "Help Ukrain" nocase

        $cond1 = "(latitude < BlArray[i].latitude_tl)"
        $cond2 = "(latitude > BlArray[i].latitude_br)"
        $cond3 = "(longitude > BlArray[i].longitude_tl)"
        $cond4 = "(longitude < BlArray[i].longitude_br)"
        $cond5 = "5900"
        $cond6 = "3200"
        $cond7 = "5300"
        $cond8 = "4400"
        $cond9 = "1049"
        $cond10 = "5450"
        $cond11 = "2633"
        $cond12 = "5280"
        $cond13 = "2900"
        $cond14 = "1049"

    condition:
        any of ($s*) or all of ($cond*)
}

rule protestware__pnpm: ino {
  meta:
    reference = "https://github.com/pnpm/pnpm/commit/3c328ec465c597ff558c1f38afbfe2a0c1b02a83"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "25.02.2022"
  strings:
        $s2 = "invaded by the Russia" nocase
        $s3 = "savelife.in.ua" nocase
        $s4 = "bank.gov.ua" nocase


        $wl1 = "bank.gov.ua/en/iban" nocase

    condition:
        any of ($s*) and 0 of ($wl*)
}

rule protestware__awesome_prometheus_alerts: html {
  meta:
    reference = "https://github.com/samber/awesome-prometheus-alerts/commit/6bfcdcca165e57c6fa09a561515c33284caa20c2"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "25.02.2022"
  strings:
        $s1 = "['ru', 'ru-ru', 'ru_ru'].includes(navigator.language.toLowerCase())" nocase
        $s2 = "Forbidden to Russia" nocase
        $s3 = "window.location = '/🖕'" nocase

    condition:
        any of ($s*)
}

rule protestware__solid_site: tsx {
  meta:
    reference = "https://github.com/solidjs/solid-site/commit/06ea1b5719612e2bb49a8f71f21915f12c39de55"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "03.03.2022"
  strings:
        $s1 = "stopputin" nocase

    condition:
        any of ($s*)
}

rule protestware__OrbitalMarket: md {
  meta:
    reference = "https://github.com/hugoattal/OrbitalMarket/commit/325547d22239e398c02a982f76c860b4a108c20a"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "04.03.2022"
  strings:
        $s1 = "stands with Ukraine" nocase
        $s2 = "www.icrc.org/en/donate/ukraine" nocase

    condition:
        any of ($s*)
}

rule protestware__belsk_schedule: php {
  meta:
    reference = "https://github.com/Danoxv/belsk-schedule/commit/47da961fc3dd9d285dc76070cd3b17833ddcf631"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "07.05.2022"
  strings:
        $s1 = "we-stand-with-ukraine" nocase
        $s2 = "Помочь Украин" nocase
        $s3 = "help-ukrain" nocase
        $s4 = "ua-help.pp.ua" nocase
        $s5 = "stand-with-ukrain" nocase

    condition:
        any of ($s*)
}

rule protestware__immer: js {
  meta:
    reference = "https://github.com/immerjs/immer/commit/4ef5cdcce030127bec0fa1402e2a4a5766dcf33a"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "12.08.2022"
  strings:
        $s1 = "Support Ukraine" nocase
        $s2 = "support-ukraine" nocase
        $s3 = "support_ukraine" nocase
        $s4 = "Aid to Ukraine" nocase
        $s5 = "Support the Ukraine" nocase


    condition:
        any of ($s*)
}

rule protestware__ngrx_platform: ts {
  meta:
    reference = "https://github.com/ngrx/platform/blob/a3fdfb47fc177c49a461a1613c11df4040dfcc49/projects/ngrx.io/src/app/custom-elements/ngrx/mff.component.ts"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "03.03.2022"
  strings:
        $s1 = "invaded by Russia" nocase
        $s2 = "supportukrainenow" nocase

    condition:
        any of ($s*)
}

rule protestware__solid_site_picture: media {
  meta:
    reference = "https://github.com/solidjs/solid-site/commit/06ea1b5719612e2bb49a8f71f21915f12c39de55"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "17.03.2022"
  condition:
    hash.sha256(0, filesize) == "842f8ae9b67297e1876b2b9b06975a4cbb26e1be4536fb5df7246ead62921d14"
}

rule protestware__3ds: html {
  meta:
    reference = "https://github.com/rashevskyv/3ds/commit/b11f9e0469d34c6183a1ef351f2cc8588c7e3eb0#diff-be2d5c2bd36999496448b5444a832c7d0d8d57ffa7ad0b15e48ed0a8c81b4a40R45"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "16.07.2022"
  strings:
        $s4 = "российская армия" nocase
        $s6 = "Российские ракеты" nocase
        $s7 = "Российская агрессия" nocase
        $s8 = "агрессию России" nocase
        $s9 = "war.ukraine.ua" nocase
        $s10 = "podderzhyte-ukraynu" nocase
        $s11 = "manifest.in.ua" nocase


    condition:
        any of ($s*)
}

rule protestware__nestjs_pino_picture: media {
  meta:
    reference = "https://github.com/iamolegga/nestjs-pino/commit/246847e2bc77429a11a3ac38da6170c9ccc60c2c"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "23.03.2022"
  condition:
    hash.sha256(0, filesize) == "e36c35d60abfeabd8cad860e56d56cf9e978d7d392ec550d07b83797323601c1"
}

rule protestware__nestjs_pino: js {
  meta:
    reference = "https://github.com/iamolegga/nestjs-pino/commit/246847e2bc77429a11a3ac38da6170c9ccc60c2c"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "23.03.2022"
  strings:
        $s1 = "war.ukraine.ua" nocase
        $s2 = "comebackalive.in.ua" nocase
        $s3 = "Слава Украин" nocase

    condition:
        any of ($s*)
}

rule protestware__LightBulb: cs {
  meta:
    reference = "https://github.com/Tyrrrz/LightBulb/commit/c62f14507d56927040c01fc410399ee4a80c6613"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "06.03.2022"
  strings:
        $s1 = "act of aggression" nocase
        $s2 = "fight for freedom" nocase
        $s3 = "supportukrainenow.org" nocase

    condition:
        any of ($s*)
}

rule protestware__wxWidgets_website: cs {
  meta:
    reference = "https://github.com/wxWidgets/website/commit/e55c1d3498ab313093084671aa34aaaa9ce849be"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "10.03.2022"
  strings:
        $s1 = "Stop Russia" nocase
        $s2 = "Russia agression" nocase

    condition:
        any of ($s*)
}

rule protestware__casl: js {
  meta:
    reference = "https://github.com/stalniy/casl/commit/b13c3de252b8412079b4030ff73309d65713c8d2"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "02.03.2022"
  strings:
        $s1 = "Russian invasion" nocase
        $s2 = "Russia invasion" nocase
        $s4 = "dearrussian.wtf" nocase
        
    condition:
        any of ($s*)
}

rule protestware__wxWidgets_website_picture: media {
  meta:
    reference = "https://github.com/wxWidgets/website/blob/e55c1d3498ab313093084671aa34aaaa9ce849be/assets/img/Ukraine-flag.png"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "10.03.2022"
  condition:
    hash.sha256(0, filesize) == "359f58034b5d4bac76f3877bc7ddc7ac110e13470be77cfd1b19dbea10ad48fc"
}

rule protestware__styled_components: js {
  meta:
    reference = "https://github.com/styled-components/styled-components/commit/f6eb4c1e8fed9eb782001e36df4a238cfe13eb64"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "24.03.2022"
  strings:
        $s1 = "российских военных" nocase
        
    condition:
        any of ($s*)
}

rule protestware__pgcli: js {
  meta:
    reference = "https://github.com/dbcli/pgcli/commit/6884c298e6845a4d870ac815a1ed269063fe3ddc"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "10.03.2022"
  strings:
        $s1 = "savelife.in.ua" nocase
        $s2 = "comebackalive.in.ua" nocase
        $s3 = "globalgiving.org" nocase
        $s4 = "savethechildren.org" nocase
        $s5 = "atlantaforukraine" nocase
        
    condition:
        any of ($s*)
}

rule protestware__redirect_russia: js {
  meta:
    reference = "https://github.com/pabio/redirect-russia"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "10.03.2022"
  strings:
        $s1 = "redirectrussia.org" nocase
        
    condition:
        any of ($s*)
}

rule protestware__TabHamster: js {
  meta:
    reference = "https://github.com/onikienko/TabHamster/commit/d406d1c3a95c44c28374e7aef7824095a63a6648"
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
    first_seen = "13.03.2022"
  strings:
        $s1 = "Russian invader" nocase
        $s2 = "Glory to Ukraine" nocase
        $s3 = "Слава Україн" nocase
        
    condition:
        any of ($s*)
}
/*
rule protestware__ukraine: js {
  meta:
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
  strings:
        $s1 = "Ukrain" nocase
        $s2 = "Украин" nocase
        $s3 = "Russian government" nocase
        $s4 = "Zelenskyy" nocase
        

        $whitelist_country1 = "Estonia" nocase
        $whitelist_country2 = "German" nocase
        $whitelist_country3 = "Brazil" nocase
        $whitelist_country4 = "Czech" nocase
        $whitelist_country5 = "Spanish" nocase
        $whitelist_country6 = "Spain" nocase
        $whitelist_country7 = "French" nocase
        $whitelist_country8 = "France" nocase
        $whitelist_country9 = "Japan" nocase
        $whitelist_country10 = "Vietnam" nocase
        $whitelist_country11 = "China" nocase
        $whitelist_country12 = "Chinese" nocase
        $whitelist_country13 = "франц" nocase
        $whitelist_country14 = "Brazīl" nocase
        $whitelist_country15 = "Уругвай" nocase
        $whitelist_country16 = "Финляндия" nocase
        $whitelist_country17 = "Словакия" nocase
        $whitelist_country18 = "Тунис" nocase
        
        // edge_cases
        $whitelist_phrases1 = "Translat" nocase
        $whitelist_phrases2 = "Local" nocase
        $whitelist_phrases3 = "Language" nocase
        $whitelist_phrases4 = "LATIN" nocase
        $whitelist_phrases5 = "CYRILLIC" nocase
        $whitelist_phrases6 = "LETTER" nocase
        $whitelist_phrases7 = "plural" nocase
        $whitelist_phrases8 = "Windows" nocase
        $whitelist_phrases9 = "Radio" nocase
        $whitelist_phrases10 = "Prompt" nocase
        $whitelist_phrases11 = "SOURCES:"
        $whitelist_phrases12 = "sVukraink"
        $whitelist_phrases13 = "sVkosztowne"
        $whitelist_phrases14 = "Ukrainian model" nocase
        $whitelist_phrases15 = "lemmatize" nocase
        $whitelist_phrases16 = "M. Bronstein, B. Salvy, Full partial fraction" nocase
        $whitelist_phrases17 = "Ідентифікаційний номер фізичної особи" nocase
        $whitelist_phrases18 = "60 лет СССР" nocase
        $whitelist_phrases19 = "Подлесная" nocase
        $whitelist_phrases20 = "Say hello in Ukrainian" nocase
        $whitelist_phrases21 = "This is the Ukrainian Whois query server" nocase


    condition:
        any of ($s*) and 0 of ($whitelist_country*) and 0 of ($whitelist_phrases*)
}

rule protestware__flags: js {
  meta:
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
  strings:
        $s1 = "🇺🇦" 
        

        $whitelist_country1 = "🇺🇸" 
        $whitelist_country2 = "🇸🇩" 
        $whitelist_country3 = "🇵🇸" 
        $whitelist_country4 = "🇮🇪" 
        $whitelist_country5 = "🇮🇱" 
        $whitelist_country6 = "🇱🇺" 
        $whitelist_country7 = "🇨🇿" 
        $whitelist_country8 = "🇩🇪" 
        $whitelist_country9 = "🇮🇳" 
        $whitelist_country10 = "🇬🇧" 

    condition:
        any of ($s*) and 0 of ($whitelist_country*)
}
*/
rule protestware__stop_war: js {
  meta:
    author = "Egor Pimashin @ PT ESC"
    date = "12.02.2025"
  strings:
        $s1 = /(^|[^A-Za-z])stopWar($|[^A-Za-z])/i
        $s2 = /(^|[^A-Za-z])no-war($|[^A-Za-z])/i
        $s4 = /(^|[^A-Za-z])stop war($|[^A-Za-z])/i
        $s5 = /(^|[^A-Za-z])stop the war($|[^A-Za-z])/i
        $s6 = /(^|[^A-Za-z])anti-war($|[^A-Za-z])/i
        $s7 = /(^|[^A-Za-z])against war($|[^A-Za-z])/i
        $s9 = /(^|[^A-Za-z])No to war($|[^A-Za-z])/i
        $s10 = /(^|[^A-Za-z])рашис($|[^A-Za-z])/i
        $s11 = /(^|[^A-Za-z])Russia invaded($|[^A-Za-z])/i
        
        
        $edge_case1 = "state-of-the-art" nocase
        $edge_case2 = "mcgilligan" nocase
        $edge_case3 = "cinematographi" nocase
        $edge_case5 = "What can we do to stop the war on drugs" nocase
        $edge_case6 = "odoo12-addon-web-widget-mermaid" nocase
        $edge_case7 = "mentorship" nocase
        $edge_case8 = "<snibri1>" nocase
        
  condition:
        any of ($s*) and 0 of ($edge_case*)
}

rule protestware__stoppropaganda: yaml {
  meta:
    reference = "https://github.com/erkexzcx/stoppropaganda"
    author = "Egor Pimashin @ PT ESC"
    date = "25.04.2022"
    first_seen = "13.03.2022"
  strings:
        $s1 = "Russian aggress" nocase
        $s2 = "StopPropaganda" nocase
        $s3 = "invaded Ukrain" nocase
        $s4 = "Русский военный корабль" nocase
        $s5 = "Russian warship" nocase


    condition:
        any of ($s*)
}

rule protestware__putler_doser: go {
  meta:
    reference = "https://github.com/metastck/putler-doser"
    author = "Egor Pimashin @ PT ESC"
    date = "02.03.2022"
    first_seen = "13.03.2022"
  strings:
        $s1 = "putler" nocase
        $s2 = "Slava Ukrain" nocase

        $exc1 = "putler-connector" nocase

    condition:
        any of ($s*) and not any of ($exc1)
}

rule protestware__RusskijKorablIdiNaxuj: go {
  meta:
    reference = "https://github.com/RusskijKorablIdiNaxuj/RusskijKorablIdiNaxuj"
    author = "Egor Pimashin @ PT ESC"
    date = "03.03.2022"
    first_seen = "13.03.2022"
  strings:
        $s1 = "RusskijKorabl" nocase
        $s2 = "KorablIdiNaxuj" nocase
        $s3 = "against Russia" nocase
        $s4 = "Russia propaganda" nocase
        $s5 = "ukraineddos" nocase
        $s6 = "itarmyofukraine" nocase
        $s7 = "UA-IT-Army" nocase
        $s8 = "Gloty to Ukrain" nocase
        $s9 = "StopRussia" nocase
        $s10 = "IT Army of Ukraine" nocase
        $s11 = "Russia MUST BE STOPPED" nocase
        $s12 = "Flag_of_Ukraine" nocase
        $s13 = "SlavaUkrain" nocase

    condition:
        any of ($s*)
}

rule protestware__Ukraina_mp3: go {
  meta:
    reference = "https://cybersecuritynews.com/threat-actors-weaponized-28-new-npm-packages/amp/"
    author = "Egor Pimashin @ PT ESC"
    date = "18.07.2022"
    first_seen = "13.03.2022"

  strings:
        $language_check1 = "navigator.language" nocase
        $domain_check1 = ".ru" nocase
        $domain_check2 = ".su" nocase
        $domain_check3 = ".by" nocase
        $domain_check4 = ".xn--p1ai" nocase
        $audio_url = "Ukraina.mp3" nocase

  condition:
        (all of ($domain_check*) and $language_check1) or $audio_url
}

rule protestware__e2eakarev: js {
  meta:
    reference = "https://www.npmjs.com/package/e2eakarev/v/7.1.0?activeTab=code"
    author = "Egor Pimashin @ PT ESC"
    date = "01.08.2022"
    first_seen = "13.10.2023"

  strings:
        $free_palestine = /(^|[^A-Za-z])free palestine($|[^A-Za-z])/i
        $peace_in_gaze = /(^|[^A-Za-z])peace in gaza($|[^A-Za-z])/i
        $peace_in_gaza_and_ukraine = /(^|[^A-Za-z])peace in palestine and ukraine($|[^A-Za-z])/i
        

  condition:
        $free_palestine or $peace_in_gaze or $peace_in_gaza_and_ukraine
}

