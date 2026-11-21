# Запросы

[English](../requests.md) | **Русский**

```python
r = s.request("GET", "https://httpbin.org/get", params={"q": "yume"}, timeout=10)
r = s.get(url)
r = s.post(url, json={"name": "yume"})
```

`request(method, url, **kwargs)` и методы-обёртки `get`, `head`, `post`, `put`, `patch`,
`delete`, `options` есть у `Session`, `AsyncSession` (с `await`) и на уровне модуля
(`yumeclient.get(...)`, `await yumeclient.aget(...)`). Метод может быть любым токеном
(`"PROPFIND"`, `"PURGE"`), он передаётся в верхнем регистре.

## Параметры запроса

| Параметр | Тип | Описание |
|---|---|---|
| `params` | `dict`, список пар | query string; списки значений раскрываются (`{"a": [1, 2]}` → `a=1&a=2`), добавляются к уже имеющемуся `?` |
| `data` | `dict`, список пар, `bytes`, `str` | тело: форма, сырые байты или текст ([ниже](#тело-запроса)) |
| `json` | любой JSON-сериализуемый объект | тело JSON, `Content-Type: application/json` |
| `files` | `dict` или список пар | multipart/form-data ([ниже](#файлы-multipart)) |
| `headers` | `dict` | заголовки этого запроса поверх заголовков сессии; `None` удаляет |
| `cookies` | `dict`, список словарей, `CookieJar` | cookie только для этого запроса, в jar сессии не попадают |
| `timeout` | число, кортеж, `TimeoutConfig`, `None` | вместо таймаута сессии ([Таймауты](timeouts-and-errors.md)) |
| `proxy` | `str` | прокси только для этого запроса ([Прокси](proxies.md)) |
| `allow_redirects` | `bool`, по умолчанию `True` | следовать редиректам |
| `header_order` | список имён | порядок заголовков этого запроса |
| `host_override` | `str` | значение заголовка `Host` (`:authority` у HTTP/2 и HTTP/3); соединение, SNI и проверка сертификата — по хосту из URL |
| `stream` | `bool`, по умолчанию `False` | не читать тело сразу ([Стриминг](responses.md#потоковое-чтение)) |
| `max_content_size` | `int` | лимит распакованного тела для этого запроса |

Неизвестный параметр — `TypeError`, как у обычной функции. Неверный URL (не `http://` или
`https://`, без хоста, с неверным портом или управляющими символами), метод или заголовок —
`InvalidRequestError` (`kind="invalid_request"`, `stage="request"`) до обращения к сети. До 0.8.1
неверный URL давал `ConnectError` с `retryable=True`.

## Тело запроса

```python
s.post(url, data={"login": "yume", "remember": "1"})   # application/x-www-form-urlencoded
s.post(url, data=[("tag", "a"), ("tag", "b")])        # форма с повторяющимися полями
s.post(url, json={"items": [1, 2, 3]})                # application/json, компактно: {"items":[1,2,3]}
s.post(url, data=b"\x00\x01binary")                   # application/octet-stream
s.post(url, data="plain text")                        # UTF-8, без Content-Type
s.post(url, data=b"...", headers={"Content-Type": "image/png"})
```

| `data` / `json` | `Content-Type` по умолчанию | Кодирование |
|---|---|---|
| `json=` | `application/json` | `json.dumps` без пробелов (как `JSON.stringify`) |
| `data=dict` или список пар | `application/x-www-form-urlencoded` | `urlencode(doseq=True)` |
| `data=bytes` | `application/octet-stream` (у okhttp-стиля — нет) | как есть |
| `data=str` | нет | UTF-8 |

`Content-Type`, заданный вами, всегда важнее умолчания. `headers={"Content-Type": None}`
убирает умолчание для `bytes`; для формы, JSON и multipart тип всё равно ставится — без него
сервер не разберёт тело (так же ведёт себя `requests`).

`Content-Length` считает транспорт. Тело отправляется целиком: потоковой отправки
(генераторы, файлы по кускам) нет — передавайте `bytes`.

## Файлы (multipart)

```python
with open("report.pdf", "rb") as f:
    r = s.post(url, data={"title": "Отчёт"}, files={"file": f})

r = s.post(url, files=[
    ("photos", ("a.jpg", jpg_bytes, "image/jpeg")),
    ("photos", ("b.jpg", other_bytes, "image/jpeg")),
    ("meta", ("meta.json", b'{"v": 1}', "application/json", {"X-Part": "1"})),
])
```

Спецификация файла — как в `requests`:

| Значение | Имя файла | Content-Type части |
|---|---|---|
| `bytes`, `str` или открытый файл | `name` открытого файла; у `bytes` и `str` — имя поля | по расширению (`mimetypes`) |
| `(имя, содержимое)` | указанное | по расширению |
| `(имя, содержимое, тип)` | указанное | указанный |
| `(имя, содержимое, тип, {заголовки})` | указанное | указанный + доп. заголовки части |

- `files` и `data` можно передавать вместе: поля `data` идут первыми.
- Списки пар сохраняют порядок частей и позволяют повторять имена.
- `str` кодируется в UTF-8; кавычки, CR и LF в именах экранируются, как у браузеров.
- Граница — как у Chrome: `----WebKitFormBoundary` и 16 hex-символов.

Кодировщик доступен отдельно:

```python
from yumeclient import encode_multipart, choose_boundary

body, content_type = encode_multipart({"a": "1"}, {"file": ("x.txt", b"hi")})
```

## Заголовки

У сессии с первого запроса есть базовые заголовки профиля: `User-Agent`, `sec-ch-ua`,
`Accept`, `Sec-Fetch-*`, `Accept-Encoding`, `Accept-Language` — те, что шлёт браузер при
переходе на страницу, в его порядке ([Профили](profiles.md#базовые-заголовки)).

```python
s.headers                                  # Headers: регистронезависимый словарь
s.headers["Accept"] = "application/json"   # заменить значение (порядок не меняется)
s.headers.update({"X-Token": "abc"})       # добавить в конец
del s.headers["Upgrade-Insecure-Requests"]
s.headers = {"User-Agent": "my-app/1.0"}   # заменить набор целиком

s.get(url, headers={"Accept": "text/css"})         # только для этого запроса
s.get(url, headers={"User-Agent": None})           # без User-Agent в этом запросе
```

### Регистр и `Headers`

`s.headers` и результат `default_headers()` (для любого профиля) — `Headers`, подкласс `dict`, в котором все
операции (`[]`, `get`, `in`, `del`, `pop`, `setdefault`, `update`, `|`) не зависят от регистра.
Имя хранится в том написании, в каком его добавили первым: `h["user-agent"] = ...` заменит
значение `User-Agent`, не меняя написания.

По HTTP/1.1 имена уходят в том написании, в каком они в словаре (браузер пишет
`User-Agent`, но `sec-ch-ua`). HTTP/2 и HTTP/3 переводят имена в нижний регистр — этого
требует протокол.

### Удаление: `None`

`None` в заголовках запроса (или сессии) убирает заголовок совсем, в том числе те, что иначе
добавил бы транспорт:

- `Accept-Encoding` и `priority`, которые добавляет сетевой слой;
- умолчания okhttp-стиля: `User-Agent: okhttp/4.12.0`, `Connection`, `Accept-Encoding`.

Исключения, как в `requests`: `Content-Type` для формы, JSON и multipart остаётся,
`{"Cookie": None}` убирает только ваш заголовок (cookie из jar уходят), `Host` и
`Content-Length` уходят всегда.

### Проверка

Имя заголовка должно быть токеном RFC 9110, значение — без управляющих символов (табуляция
и не-ASCII разрешены). Иначе `InvalidRequestError` до отправки. По HTTP/2 и HTTP/3 нельзя
передать `Connection` (кроме `keep-alive` и `close`, их транспорт просто не отправляет),
`Upgrade`, `Transfer-Encoding` (кроме `chunked`) — тоже `InvalidRequestError`, соединение при
этом остаётся рабочим.

### Порядок

- Без `header_order` заголовки уходят в порядке словаря: сначала заголовки сессии, затем
  новые из запроса.
- `header_order=[...]` у сессии или запроса задаёт порядок явно; заголовки, которых нет в
  списке, идут после перечисленных в порядке словаря.
- По HTTP/1.1 `Host` идёт первым, как у всех браузеров, если только вы не поставили его в
  `header_order` в другое место.
- Транспорт добавляет свои поля на места, где их ставит браузер: `Content-Length`,
  `Cookie`, `priority` у Chromium (последним по HTTP/2 и HTTP/3), `te: trailers` у Firefox по
  HTTP/2.
- Если `Accept-Encoding` нет ни в сессии, ни в запросе, транспорт добавляет в конец
  `Accept-Encoding: gzip, deflate, br` (у okhttp-стиля — `gzip`). Чтобы его не было,
  передайте `{"Accept-Encoding": None}`. `User-Agent` транспорт сам не добавляет (кроме
  okhttp-стиля).

Что ушло на самом деле, видно в `r.fingerprint["request_headers"]` — список пар в порядке и
регистре провода ([Ответы](responses.md#fingerprint)).

## Редиректы

Запрос следует не более чем 20 редиректам, как браузер (стандарт Fetch); на 21-м —
`TooManyRedirects`. До 0.8.1 предел был как в Go: на 10-м редиректе ошибка, то есть
выполнялось 9.
`allow_redirects=False` возвращает сам ответ 3xx.

Метод следующего запроса выбирается как в браузерах (стандарт Fetch):

| Код | Метод и тело следующего запроса |
|---|---|
| 301, 302 | `POST` становится `GET` без тела; остальные методы сохраняются вместе с телом |
| 303 | всё, кроме `GET` и `HEAD`, становится `GET` без тела |
| 307, 308 | метод и тело сохраняются |

- Когда метод меняется, вместе с телом уходят `Content-Type`, `Content-Encoding`,
  `Content-Language`, `Content-Location`, `Content-Length` и `Origin` (как в Chromium).
- До 0.8.1 при 301/302 любой метод (в том числе `PUT`, `PATCH`, `DELETE`) становился `GET`
  без тела, как в Go.
- `Referer` на хопах сам не добавляется (браузер сохраняет исходный referrer, `requests`
  тоже); ваш `Referer` переносится как есть.
- При переходе на другой хост или порт (кроме поддомена исходного хоста с тем же портом)
  отбрасываются `Authorization` и ваш заголовок `Cookie`. Порт сравнивается с учётом
  умолчаний, поэтому переход `http://host/` → `https://host/` (80 → 443) их тоже отбрасывает.
  Cookie из jar выбираются для нового адреса заново.
- Каждый хоп — с TLS и HTTP/2-параметрами профиля, в том числе переходы между `http://` и
  `https://`.
- Cookie, выставленные на любом хопе, попадают в jar.
- Пройденные редиректы — в `r.history` ([Ответы](responses.md#история-редиректов)).

## Cookie запроса

```python
s.get(url, cookies={"ab_test": "b"})
```

Cookie запроса добавляются к cookie из jar сессии (при совпадении имени побеждают они) и не
сохраняются в jar. То, что сервер выставит в ответ, в jar попадёт как обычно. Подробнее —
[Cookies](cookies.md).
