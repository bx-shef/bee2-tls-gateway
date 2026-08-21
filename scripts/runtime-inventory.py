#!/usr/bin/env python3
"""Parse the runtime inventory declared in README § «Что исполняется в образе».

Единственный источник истины по составу образа — README. Скрипт читает его и печатает
объявленное, чтобы одно и то же чтение использовали и текстовые проверки в job `ci`,
и поведенческая сверка с собранным образом в job `image`.

⚠ Почему парсер, а не отдельный файл со списком. Отдельный файл был бы ЧЕТВЁРТОЙ копией
рядом с тремя, которые эта задача сводит в одну. Список, который читает человек, и список,
который сверяет CI, обязаны быть одним текстом — иначе расходятся именно они.
"""
import re
import sys

FILES_HEADING = "### Файлы, положенные нами"
CMDS_HEADING = "### Подкоманды `bee2cmd`"


def _section(text, heading):
    """Тело раздела от его заголовка до следующего заголовка любого уровня."""
    start = text.find(heading)
    if start == -1:
        return ""
    start += len(heading)
    nxt = re.search(r"^#{2,4} ", text[start:], re.M)
    return text[start:start + nxt.start()] if nxt else text[start:]


def _first_column(section):
    """Значения в обратных кавычках из первой колонки таблицы, без строк разметки."""
    out = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|") or set(line) <= set("|- "):
            continue
        cell = line.split("|")[1].strip()
        m = re.fullmatch(r"`([^`]+)`", cell)
        if m:
            out.append(m.group(1))
    return out


def parse(readme_text):
    files = _first_column(_section(readme_text, FILES_HEADING))
    cmds = _first_column(_section(readme_text, CMDS_HEADING))
    return files, cmds


if __name__ == "__main__":
    readme = open(sys.argv[1] if len(sys.argv) > 1 else "README.md",
                  encoding="utf-8").read()
    files, cmds = parse(readme)
    what = sys.argv[2] if len(sys.argv) > 2 else "both"
    if what in ("files", "both"):
        for f in files:
            print(f)
    if what in ("cmds", "both"):
        for c in cmds:
            print(c)
