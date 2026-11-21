# Cookies

[English](../cookies.md) | **Русский**

Все cookie сессии хранятся в `s.cookies` — объекте `CookieJar`. Это единственное хранилище:
каждый запрос получает его снимок. На каждом хопе, включая редиректы, нативная часть выбирает
cookie по правилам RFC 6265 и возвращает только изменения. Изменения сразу видны в
`s.cookies`.

```python
from yumeclient import Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?session=abc")   # Set-Cookie на редиректе → в jar
    print(s.cookies["session"])                            # 'abc'
    print(s.get("https://httpbin.org/cookies").json())     # {'cookies': {'session': 'abc'}}
```

## Какие cookie уходят в запрос

Cookie уходит на URL, если выполнены все условия:

- **домен.** Cookie без атрибута `Domain` (host-only) уходит только на тот хост, который её
  выставил. Cookie с `Domain=example.com` уходит на `example.com` и все его поддомены;
- **путь.** Путь запроса начинается с `Path` cookie (по сегментам: `/a` подходит к `/a/b`, но
  не к `/ab`);
- **Secure.** Cookie с `Secure` уходит только по `https://`. Если её выставили по `http://`,
  она сохраняется, но по `http://` не отправляется;
- **срок.** Cookie не истекла. Cookie без `Expires`/`Max-Age` живёт до конца сессии.

Порядок в заголовке `Cookie` — как у браузеров: сначала cookie с более длинным путём, при
равных путях — более старые.

Сервер не может выставить cookie:

- чужому домену: ответ `a.com` с `Domain=b.com` отбрасывается;
- публичному суффиксу (`Domain=com`, `co.uk`, `github.io` — по списку Mozilla Public Suffix
  List, как в браузерах): такая cookie отбрасывается. Исключение — сам хост-суффикс, для него
  cookie становится host-only;
- с `Domain=` на IP-адресе: cookie становится host-only.

Удаление сервером (`Max-Age=0` или `Expires` в прошлом) убирает cookie из jar.

## Cookie, заданные вручную

```python
s.cookies["token"] = "x"                           # без домена: уходит на любой хост
s.cookies.set("sid", "1", domain="example.com")    # example.com и поддомены
s.cookies.set("sid", "1", domain="example.com", host_only=True)   # только example.com
s.cookies.set("pref", "dark", domain="example.com", path="/app",
              secure=True, http_only=True, same_site="Lax",
              expires=1767225600)                  # Unix-время в секундах
```

Cookie без домена ведёт себя как в `requests`: уходит на любой хост. Если для хоста есть
одноимённая cookie с доменом, уходит она, а не cookie без домена.

`s.cookies[name] = value` меняет значение существующей cookie с этим именем и путём `/`.
Если таких несколько, меняется та, у которой самый длинный домен. Если такой нет, создаётся
cookie без домена. Чтобы задать cookie для конкретного домена, используйте `set(..., domain=...)`.

Cookie без домена — не то же самое, что cookie, которую выставил бы сервер. Сервер может её
перекрыть своей cookie для хоста, но не может удалить через `Max-Age=0`: удаление касается
cookie его хоста. Так же ведёт себя `requests`. Удаляйте такие cookie сами: `s.cookies.remove(name)`.

## Cookie одного запроса

```python
s.get(url, cookies={"temp": "1"})
```

Такие cookie уходят только в этот запрос и заменяют одноимённые cookie сессии. В jar они не
попадают, если сервер не выставит их сам. Принимаются `dict`, `CookieJar` (берутся cookie для
этого URL) и список словарей `{"name": ..., "value": ...}`.

Заголовок `Cookie`, заданный вручную (`headers={"Cookie": "a=1"}`), уходит как есть, а cookie из
jar добавляются после него в тот же заголовок: `Cookie: a=1; sid=...`. При редиректе на
другой хост ручной заголовок удаляется, а cookie из jar выбираются заново для нового хоста.
Обычно удобнее `cookies=` или `s.cookies.set(...)`.

## API `CookieJar`

| Метод | Что делает |
|---|---|
| `CookieJar(initial=None)` | `initial`: `dict` имя → значение (cookie без домена) или список словарей в формате экспорта браузера |
| `jar[name]`, `jar.get(name, default=None)` | значение; при нескольких одноимённых — с самым длинным доменом. Срок не проверяется (истёкшую cookie не отправят, но прочитать её можно). `jar[name]` без cookie — `KeyError` |
| `name in jar` | есть ли cookie с таким именем |
| `jar[name] = value` | см. [выше](#cookie-заданные-вручную) |
| `jar.set(name, value, *, domain="", path="/", expires=None, secure=False, http_only=False, same_site=None, host_only=False)` | с `domain` — добавить или заменить cookie с тем же `(name, domain, path)`. Без `domain` — как `jar[name] = value`: меняется значение существующей cookie с этим именем и путём (с самым длинным доменом), остальные аргументы, кроме `expires`, при этом не применяются; если такой нет — создаётся cookie без домена |
| `jar.update(values, *, domain="")` | несколько cookie: `dict` (каждая — как `set(name, value, domain=domain)`) или список словарей |
| `jar.load("a=1; b=2", *, domain="")` | разобрать значение заголовка `Cookie` |
| `jar.remove(name, *, domain=None, path=None)` | удалить; без `domain`/`path` — все cookie с этим именем |
| `jar.clear_domain(domain)` | удалить cookie с этим доменом (cookie поддоменов не затрагиваются) |
| `jar.for_url(url)` | `list[JarCookie]`, которые уйдут на `url`, в порядке заголовка |
| `jar.to_dict(*, url=None, domain=None)` | имя → значение: для `url` — по всем правилам; для `domain` — только по хосту; без аргументов — все не истёкшие |
| `jar.get_cookie(name)` | `http.cookiejar.Cookie` или `None` |
| `jar.export()` | список словарей для сохранения |
| `len(jar)`, `for c in jar` | число cookie; перебор `JarCookie` |

`JarCookie` — dataclass с полями `name`, `value`, `domain`, `path`, `expires` (Unix-время или
`None`), `secure`, `http_only`, `same_site`, `host_only`.

`CookieJar` можно использовать из нескольких потоков и из нескольких задач `AsyncSession` сразу.
Он поддерживает `copy.deepcopy` и `pickle`.

## Импорт и экспорт

`export()` отдаёт формат расширений браузера (Cookie-Editor, EditThisCookie): `name`, `value`,
`domain`, `path`, `expirationDate`, `secure`, `httpOnly`, `sameSite`, `hostOnly`. Этот же формат
принимают конструктор `CookieJar` и `update()`. Вместо `expirationDate` можно указать `expires`.

```python
import json
from yumeclient import CookieJar, Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?a=1")
    json.dump(s.cookies.export(), open("cookies.json", "w"))

jar = CookieJar(json.load(open("cookies.json")))
with Session(cookies=jar) as s:
    print(s.get("https://httpbin.org/cookies").json())   # {'cookies': {'a': '1'}}
```

Cookie, выгруженные из браузера, переносятся так же: экспортируйте их расширением в JSON и
передайте список в `CookieJar(...)`.

## Где ещё видны cookie

- `r.cookies` — `dict` cookie для конечного URL после обмена: подходящие cookie сессии и
  запроса плюс выставленные ответами, без удалённых.
- `r.history[i].cookies` — только `Set-Cookie` этого хопа.
- `r.headers["Set-Cookie"]` — сырые заголовки последнего ответа.
