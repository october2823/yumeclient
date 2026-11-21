<!-- English or Russian. / Можно на русском или английском. -->

## What and why / Что и зачем



## Checklist / Проверка

- [ ] A test that fails without the change / Тест, который без изменения падает
- [ ] `python -m pytest -q` and `(cd native && go test ./...)` pass / проходят
- [ ] `python scripts/third_party.py check` passes, if `native/third_party/` changed / проходит, если менялся `native/third_party/`
- [ ] Docs updated in both languages: `docs/` and `docs/ru/`, `*.md` and `*.ru.md` / Документация обновлена на обоих языках
- [ ] `CHANGELOG.md` and `CHANGELOG.ru.md`, section `[Unreleased]` / раздел `[Unreleased]`
