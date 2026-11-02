import subprocess
F="DejaVu Sans"
def rec(title, attrs, methods, stereo=None):
    head = (f"«{stereo}»\\n" if stereo else "") + title
    return '{' + head + '|' + attrs + '|' + methods + '}'
src=f'''digraph G {{
 graph [fontname="{F}", rankdir=TB, splines=true, nodesep=0.5, ranksep=0.6, pad=0.2, dpi=200, size="7.4,9!"];
 node [fontname="{F}", fontsize=10, shape=record, style=filled, fillcolor="#fdfefe", color="#1f4e79"];
 edge [fontname="{F}", fontsize=9, color="#444444", arrowsize=0.8];
 Registry [label="{rec("Registry","- _counters: dict\\l- _gauges: dict\\l- _hists: dict\\l","+ describe(name, text)\\l+ inc(name, amount, **labels)\\l+ set(name, value, **labels)\\l+ observe(name, value, **labels)\\l+ render(): str\\l")}"];
 Timer [label="{rec("Timer","- r: Registry\\l- name: str\\l","+ __enter__()\\l+ __exit__()\\l")}"];
 Blocklist [label="{rec("Blocklist","- _d: set[str]\\l","+ add(domain): bool\\l+ __contains__(domain): bool\\l+ as_list(): list\\l")}"];
 EventStore [label="{rec("EventStore","- conn: sqlite3.Connection\\l- _lock: Lock\\l","+ add(event): int\\l+ last(n): list\\l+ counts(): dict\\l")}"];
 HtmlCleaner [label="{rec("_HtmlCleaner","- out: list[str]\\l- skip_depth: int\\l","+ handle_starttag(tag, attrs)\\l+ handle_endtag(tag)\\l+ handle_data(data)\\l")}"];
 HTMLParser [label="{rec("HTMLParser","","",stereo="html.parser")}", fillcolor="#eeeeee"];
 detector [label="{rec("detector","","+ normalize(content)\\l+ analyze_content(content, cfg)\\l+ analyze_url(url, cfg)\\l+ check_upload(...)\\l+ detect_type(...)\\l+ score_to_verdict(findings, cfg)\\l+ analyze_item(item, cfg)\\l",stereo="module")}", color="#1e8449"];
 sanitizer [label="{rec("sanitizer","","+ sanitize_svg(content): str или None\\l+ sanitize_html(content): str\\l",stereo="module")}", color="#1e8449"];
 policy [label="{rec("policy","","+ decide(item, analysis, cfg, blocklist)\\l",stereo="module")}", color="#1e8449"];
 collector [label="{rec("collector","","+ build_item(payload): dict\\l",stereo="module")}", color="#1e8449"];
 app_c [label="{rec("content_collector.app","","POST /ingest, GET /health, GET /metrics\\l",stereo="Flask")}", fillcolor="#eaf2fb"];
 app_a [label="{rec("analyzer_detector.app","","POST /analyze, GET /health, GET /metrics\\l",stereo="Flask")}", fillcolor="#eaf2fb"];
 app_r [label="{rec("response_block.app","","POST /decide, GET /blocklist\\l",stereo="Flask")}", fillcolor="#eaf2fb"];
 app_v [label="{rec("visual_alert.app","","POST /event, GET /events, GET /\\l",stereo="Flask")}", fillcolor="#eaf2fb"];
 Timer -> Registry [label=" использует", arrowhead=vee, style=dashed];
 HtmlCleaner -> HTMLParser [arrowhead=empty, label=" наследует"];
 sanitizer -> HtmlCleaner [arrowhead=diamond, label=" содержит", dir=back];
 policy -> detector [arrowhead=vee, style=dashed, label=" использует"];
 policy -> sanitizer [arrowhead=vee, style=dashed];
 policy -> Blocklist [arrowhead=vee, style=dashed];
 app_c -> collector [arrowhead=vee, style=dashed]; app_c -> Registry [arrowhead=vee, style=dashed];
 app_a -> detector [arrowhead=vee, style=dashed]; app_a -> Registry [arrowhead=vee, style=dashed];
 app_r -> policy [arrowhead=vee, style=dashed]; app_r -> Registry [arrowhead=vee, style=dashed];
 app_v -> EventStore [arrowhead=diamond, dir=back, label=" владеет"]; app_v -> Registry [arrowhead=vee, style=dashed];
}}'''
open("img/fig12_uml_class.dot","w",encoding="utf-8").write(src)
subprocess.run(["dot","-Tpng","img/fig12_uml_class.dot","-o","img/fig12_uml_class.png"],check=True)
print("ok")
