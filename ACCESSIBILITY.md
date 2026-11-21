# Accessibility

**English** | [Русский](ACCESSIBILITY.ru.md)

yumeclient is a Python library and has no user interface of its own. Accessibility here means
the documentation and the messages the library produces.

- The documentation is Markdown: it reads on GitHub and PyPI and in any text editor. Pages are
  structured with headings, tables have header rows, and code is in code blocks, not in images.
- The only images are the badges at the top of the README, each with a text alternative.
- Every documentation page exists in English and Russian and links to its translation under
  the title. The license texts (`LICENSE`, `THIRD_PARTY_NOTICES.md`) are only in English.
- Errors are Python exceptions and warnings with plain-text messages, so a screen reader or a
  log shows the whole message.

Known limitations:

- The documentation is only in English and Russian.
- Exception and warning messages are only in English.

If something in the documentation or in the library is hard to use with assistive technology,
[open an issue](https://github.com/october2823/yumeclient/issues/new/choose).
