import subprocess, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams["font.family"] = "DejaVu Sans"
FONT="DejaVu Sans"
G='#1e8449'; GB='#e9f7ef'; B='#1f4e79'; BB='#eaf2fb'; R='#c0392b'; RB='#fdecea'; Y='#9a7d0a'; YB='#fef9e7'

def dot(name, body, size="7.4,9!", rankdir="TB", extra=""):
    src=f'''digraph G {{ graph [fontname="{FONT}", rankdir={rankdir}, splines=true, nodesep=0.35, ranksep=0.4, pad=0.2, dpi=200, size="{size}", {extra}];
 node [fontname="{FONT}", fontsize=11, shape=box, style="rounded,filled", fillcolor="#ffffff", color="#444444", margin="0.12,0.07"];
 edge [fontname="{FONT}", fontsize=10, color="#444444", arrowsize=0.8];
{body}}}'''
    open(f"img/{name}.dot","w",encoding="utf-8").write(src)
    subprocess.run(["dot","-Tpng",f"img/{name}.dot","-o",f"img/{name}.png"],check=True)

# ---- Архитектура паттерна ----
dot("fig5_architecture", f'''
 subgraph cluster_src {{ label="Источники недоверенного содержимого"; style="rounded,dashed"; color="{R}"; fontcolor="{R}"; bgcolor="{RB}"; labeljust=l;
   ads [label="Рекламные сети\\n(HTML, JS, баннеры)", fillcolor="#fadbd8", color="{R}"];
   svc [label="Сторонние сервисы\\nи виджеты", fillcolor="#fadbd8", color="{R}"];
   usr [label="Пользовательский контент\\n(загрузка SVG, изображений)", fillcolor="#fadbd8", color="{R}"]; }}
 app [label="Защищаемое веб-приложение\\n(точка интеграции паттерна:\\nвызов POST /ingest до вставки содержимого)", fillcolor="{BB}", color="{B}"];
 subgraph cluster_pat {{ label="Паттерн безопасности: четыре микросервиса"; style="rounded,bold"; color="{G}"; fontcolor="{G}"; bgcolor="{GB}"; labeljust=l;
   c1 [label="1. content_collector\\nприём, идентификация,\\nSHA-256, тип, URL", color="{G}"];
   c2 [label="2. analyzer_detector\\nнормализация, сигнатуры,\\nпризнаки URL, балл", color="{G}"];
   c3 [label="3. response_block\\nALLOW / SANITIZE / BLOCK,\\nсанитайзер, чёрный список", color="{G}"];
   c4 [label="4. visual_alert\\nжурнал, панель, Telegram", color="{G}"]; }}
 db  [label="Журнал событий\\n(SQLite / том)", shape=cylinder, fillcolor="#d5f5e3", color="{G}"];
 cfg [label="ConfigMap\\npattern_config.json\\n(пороги, доверенные домены)", shape=note, fillcolor="{YB}", color="{Y}"];
 subgraph cluster_mon {{ label="Мониторинг"; style="rounded"; color="{B}"; fontcolor="{B}"; bgcolor="{BB}"; labeljust=l;
   pr [label="Prometheus\\nсбор /metrics", color="{B}"]; gf [label="Grafana\\nдашборд", color="{B}"]; }}
 br [label="Браузер пользователя\\n(получает только разрешённое\\nили очищенное содержимое)", fillcolor="#d6eaf8", color="{B}"];
 ads->app; svc->app; usr->app;
 app->c1 [label=" 1. содержимое", color="{G}"]; c1->c2 [label=" 2. объект", color="{G}"];
 c2->c3 [label=" 3. вердикт", color="{G}"]; c3->c4 [label=" 4. событие", color="{G}"];
 c4->db [color="{G}"]; c3->c2 [label=" чёрный список\\n(синхронизация)", style=dashed, color="{G}", constraint=false];
 c3->app [label=" 5. решение + очищенный контент", color="{G}", constraint=false];
 app->br [label=" 6. безопасный HTML", color="{B}"];
 cfg->c2 [style=dashed, color="{Y}"]; cfg->c3 [style=dashed, color="{Y}"];
 c1->pr [style=dotted, color="{B}", arrowhead=none, constraint=false]; c2->pr [style=dotted, color="{B}", constraint=false];
 pr->gf [color="{B}"];
''', size="7.4,9.6!")

# ---- Диаграмма состояний ----
dot("fig7_uml_state", f'''
 node [shape=box, style="rounded,filled", fillcolor="#ffffff"];
 s0 [label="", shape=circle, style=filled, fillcolor="#000000", width=0.2];
 s1 [label="Получено"]; s2 [label="Идентифицировано\\n(тип, хэш, URL)"]; s3 [label="Проанализировано"];
 c  [label="CLEAN\\n(балл < 2)", fillcolor="{GB}", color="{G}"]; sp [label="SUSPICIOUS\\n(2 ≤ балл < 5)", fillcolor="{YB}", color="{Y}"]; m [label="MALICIOUS\\n(балл ≥ 5)", fillcolor="{RB}", color="{R}"];
 a [label="Разрешено (ALLOW)", fillcolor="{GB}", color="{G}"]; sa [label="Очищено (SANITIZE)", fillcolor="{YB}", color="{Y}"]; b [label="Заблокировано (BLOCK)", fillcolor="{RB}", color="{R}"];
 l [label="Зарегистрировано в журнале"]; n [label="Оповещение отправлено"]; e [label="", shape=doublecircle, style=filled, fillcolor="#000000", width=0.2];
 s0->s1 [label=" POST /ingest"]; s1->s2 [label=" collector"]; s2->s3 [label=" analyzer"];
 s3->c; s3->sp; s3->m;
 c->a; sp->sa [label=" svg/html,\\nостаток < 5"]; sp->b [label=" не очищается"]; m->b; m->sa [label=" SVG-файл без\\nструктурных нарушений", style=dashed];
 a->l; sa->l; b->l; l->n [label=" BLOCK/SANITIZE"]; l->e [label=" ALLOW"]; n->e;
''', size="7.4,9.4!")

# ---- Диаграмма деятельности ----
dot("fig8_uml_activity", f'''
 s [label="", shape=circle, style=filled, fillcolor="#000000", width=0.2];
 a1 [label="Принять содержимое (POST /ingest)"]; a2 [label="Определить тип, вычислить SHA-256,\\nизвлечь URL"];
 a3 [label="Нормализовать содержимое\\n(HTML-сущности, %xx, разрывы)"]; a4 [label="Применить 19 сигнатур\\nи проверить URL"];
 a5 [label="Для файлов: проверить расширение,\\nMIME, размер, фактический тип"]; a6 [label="Суммировать вес признаков\\n→ вердикт"];
 d1 [label="Вердикт?", shape=diamond, fillcolor="{YB}", color="{Y}"];
 b1 [label="Передать как есть"]; b2 [label="Очистить (SVG/HTML по белому списку)\\nи повторно проанализировать", fillcolor="{YB}"]; b3 [label="Не передавать содержимое;\\nдобавить домен в чёрный список (для рекламы)", fillcolor="{RB}"];
 j [label="Записать событие в журнал,\\nобновить метрики"]; d2 [label="Решение ≠ ALLOW?", shape=diamond, fillcolor="{YB}", color="{Y}"];
 n [label="Отправить оповещение"]; r [label="Вернуть решение веб-приложению"]; e [label="", shape=doublecircle, style=filled, fillcolor="#000000", width=0.2];
 s->a1->a2->a3->a4->a5->a6->d1;
 d1->b1 [label=" CLEAN"]; d1->b2 [label=" SUSPICIOUS"]; d1->b3 [label=" MALICIOUS"];
 b1->j; b2->j; b3->j; j->d2; d2->n [label=" да"]; d2->r [label=" нет"]; n->r; r->e;
''', size="7.4,10!")

# ---- Блок-схема decide() ----
dot("fig9_flow_decide", f'''
 s [label="Начало", shape=box, style="rounded,filled", fillcolor="#eeeeee"];
 i [label="Вход: item, analysis, cfg, blocklist", shape=parallelogram];
 d1 [label="label = CLEAN?", shape=diamond, fillcolor="{YB}", color="{Y}"]; al [label="decision = ALLOW\\ncontent без изменений", fillcolor="{GB}", color="{G}"];
 d2 [label="MALICIOUS и нет\\nвосстановимого SVG-файла?", shape=diamond, fillcolor="{YB}", color="{Y}"];
 bl [label="decision = BLOCK\\ncontent = None", fillcolor="{RB}", color="{R}"];
 sa [label="Очистка: sanitize_svg / sanitize_html"]; d3 [label="Очистка\\nвозможна?", shape=diamond, fillcolor="{YB}", color="{Y}"];
 re [label="Повторный анализ\\nочищенного содержимого"]; d4 [label="Остаточный балл ≥ 5?", shape=diamond, fillcolor="{YB}", color="{Y}"];
 ok [label="decision = SANITIZE\\ncontent = очищенный", fillcolor="{GB}", color="{G}"];
 d5 [label="BLOCK и kind = ad?", shape=diamond, fillcolor="{YB}", color="{Y}"]; bw [label="Добавить домен источника\\nв чёрный список"];
 e [label="Возврат результата", shape=parallelogram]; f [label="Конец", style="rounded,filled", fillcolor="#eeeeee"];
 s->i->d1; d1->al [label=" да"]; d1->d2 [label=" нет"]; d2->bl [label=" да"]; d2->sa [label=" нет"];
 sa->d3; d3->bl [label=" нет"]; d3->re [label=" да"]; re->d4; d4->bl [label=" да"]; d4->ok [label=" нет"];
 bl->d5; d5->bw [label=" да"]; d5->e [label=" нет"]; bw->e; ok->e; al->e; e->f;
''', size="7.4,10!")

# ---- Развёртывание в Kubernetes ----
dot("fig10_deployment", f'''
 subgraph cluster_k {{ label="Кластер Kubernetes — пространство имён pat-ns"; style="rounded,bold"; color="{B}"; fontcolor="{B}"; bgcolor="{BB}"; labeljust=l;
  subgraph cluster_lab {{ label="Лабораторный стенд"; style="rounded,dashed"; color="{R}"; fontcolor="{R}"; bgcolor="{RB}";
    wv [label="webapp-vulnerable\\nPROTECTION=off", color="{R}"]; wp [label="webapp-protected\\nPROTECTION=on", color="{G}"];
    adn [label="ad-network\\n(модель рекламной сети)", color="{R}"]; at [label="attacker-server\\n(тестовый приёмник)", color="{R}"]; }}
  subgraph cluster_p {{ label="Паттерн безопасности"; style="rounded"; color="{G}"; fontcolor="{G}"; bgcolor="{GB}";
    cc [label="content-collector\\nDeployment ×1 + Service", color="{G}"]; an [label="analyzer-detector\\nDeployment ×2 + Service + HPA (2–5)", color="{G}"];
    rb [label="response-block\\nDeployment ×1 + Service", color="{G}"]; va [label="visual-alert\\nDeployment ×1 + Service", color="{G}"]; }}
  cm [label="ConfigMap\\npattern-config", shape=note, fillcolor="{YB}", color="{Y}"];
  subgraph cluster_m {{ label="Мониторинг"; style="rounded"; color="{B}"; fontcolor="{B}"; bgcolor="#ffffff";
    pr [label="Prometheus\\n(kubernetes_sd: поды с аннотацией scrape)", color="{B}"]; gf [label="Grafana\\nдашборд pat-dashboard", color="{B}"]; }}
  np [label="NetworkPolicy: default-deny ingress,\\nразрешены только звенья конвейера", shape=note, fillcolor="{YB}", color="{Y}"];
 }}
 adm [label="Администратор\\nkubectl port-forward", fillcolor="#d6eaf8", color="{B}"];
 wv->adn; wp->adn; wp->cc [label=" /ingest", color="{G}"]; cc->an; an->rb; rb->va; rb->an [style=dashed, constraint=false];
 cm->an [style=dashed]; cm->rb [style=dashed]; pr->gf;
 cc->pr [style=dotted, arrowhead=none, constraint=false]; an->pr [style=dotted, arrowhead=none, constraint=false];
 adm->gf; adm->wp; adm->wv;
''', size="7.4,9!")

# ---- Диаграмма последовательности (matplotlib) ----
def seq():
    fig, ax = plt.subplots(figsize=(11, 8.6), dpi=200)
    names = ["Браузер /\nпользователь", "Веб-\nприложение", "content_\ncollector", "analyzer_\ndetector", "response_\nblock", "visual_\nalert"]
    xs = [0.7, 2.6, 4.5, 6.4, 8.3, 10.2]
    top, bot = 9.3, -0.4
    for x, n in zip(xs, names):
        ax.add_patch(FancyBboxPatch((x-0.75, top), 1.5, 0.65, boxstyle="round,pad=0.02", fc=BB, ec=B, lw=1.2))
        ax.text(x, top+0.33, n, ha="center", va="center", fontsize=9)
        ax.plot([x, x], [top, bot], color="#888", lw=1, ls=(0, (4, 3)))
    msgs = [
        (0, 1, 8.8, "1. GET /?ad=3 (запрос страницы)", "-"),
        (1, 1, 8.3, "2. получить креатив у рекламной сети", "self"),
        (1, 2, 7.8, "3. POST /ingest {kind, source, content}", "-"),
        (2, 2, 7.35, "4. тип, SHA-256, URL", "self"),
        (2, 3, 6.9, "5. POST /analyze (объект)", "-"),
        (3, 3, 6.45, "6. нормализация, сигнатуры, балл", "self"),
        (3, 4, 6.0, "7. POST /decide (объект + анализ)", "-"),
        (4, 4, 5.55, "8. решение; очистка / чёрный список", "self"),
        (4, 5, 5.1, "9. POST /event (журнал + оповещение)", "-"),
        (5, 4, 4.6, "10. {stored: id}", "--"),
        (4, 3, 4.15, "11. {decision, content, actions}", "--"),
        (3, 2, 3.7, "12. результат", "--"),
        (2, 1, 3.25, "13. {decision: BLOCK, content: null}", "--"),
        (1, 0, 2.7, "14. страница с заглушкой вместо рекламы", "--"),
    ]
    for idx, (a, b, y0, t, st) in enumerate(msgs):
        y = 8.9 - idx * 0.62
        xa, xb = xs[a], xs[b]
        if st == "self":
            ax.annotate("", xy=(xa+0.02, y-0.25), xytext=(xa+0.02, y), arrowprops=dict(arrowstyle="->", color="#444444", connectionstyle="arc3,rad=-1.8"))
            ax.text(xa+0.35, y-0.12, t, fontsize=8.3, va="center")
        else:
            ax.annotate("", xy=(xb, y), xytext=(xa, y), arrowprops=dict(arrowstyle="->", color=R if st == "-" and a == 0 else "#333", ls="--" if st == "--" else "-", lw=1.2))
            ax.text((xa+xb)/2, y+0.1, t, fontsize=8.3, ha="center", va="bottom")
    ax.add_patch(FancyBboxPatch((0.1, -0.6), 10.95, 0.9, boxstyle="round,pad=0.02", fc=YB, ec=Y, lw=1))
    ax.text(5.6, -0.15, "Альтернатива при отказе любого звена конвейера: collector возвращает BLOCK (принцип fail-closed),\nсодержимое не передаётся в браузер.", ha="center", va="center", fontsize=9)
    ax.set_xlim(0, 11.2); ax.set_ylim(-0.8, 10.1); ax.axis("off")
    fig.savefig("img/fig6_uml_sequence.png", bbox_inches="tight", facecolor="white"); plt.close(fig)
seq()

# ---- Результаты оценки ----
ev = json.load(open("../results/evaluation.json", encoding="utf-8"))
sm = ev["summary"]
fig, axs = plt.subplots(1, 2, figsize=(11, 4.4), dpi=200, gridspec_kw={"width_ratios": [1.5, 1]})
groups = list(sm.keys()); tot=[sm[g]["total"] for g in groups]; ok=[sm[g]["ok"] for g in groups]
x = range(len(groups))
axs[0].bar(x, tot, color="#d5d8dc", label="всего образцов")
axs[0].bar(x, ok, color=[G if "обход" not in g else R for g in groups], label="обработано корректно")
for i,(t,o) in enumerate(zip(tot,ok)): axs[0].text(i, t+0.4, f"{o}/{t}", ha="center", fontsize=10)
axs[0].set_xticks(list(x)); axs[0].set_xticklabels([g.replace(": ", ":\n") for g in groups], fontsize=8.5)
axs[0].set_ylabel("Количество образцов"); axs[0].set_title("Результаты на тестовом корпусе", fontsize=11); axs[0].legend(fontsize=8, loc="upper right")
lat = [ev["latency_ms_mean"], ev["latency_ms_median"], ev["latency_ms_p95"], ev["latency_ms_max"]]
axs[1].bar(["среднее","медиана","p95","макс."], lat, color=B)
for i,v in enumerate(lat): axs[1].text(i, v+0.03, f"{v}", ha="center", fontsize=9)
axs[1].set_ylabel("мс"); axs[1].set_title("Задержка сквозного конвейера", fontsize=11)
fig.tight_layout(); fig.savefig("img/fig11_results.png", facecolor="white"); plt.close(fig)
print("ok")
