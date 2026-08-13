# Защита ветки `main`

Репозиторий публичный, поэтому `main` должна быть неломаемой: никаких прямых
пушей, никакого force-push, никакого «случайно удалил ветку». Правила описаны
здесь как конфиг, чтобы их можно было воспроизвести и отревьюить в PR.

Файлы:

| Файл | Зачем |
| --- | --- |
| `.github/rulesets/main-protection.json` | Готовый GitHub Ruleset — импортируется в настройках репозитория |
| `.github/workflows/ci.yml` | Job `ci` — обязательная проверка перед мержем |

> Важно: сам ruleset **включается только вручную** в настройках репозитория —
> файл в репозитории ничего не активирует сам по себе. Ниже — что нажать.

## Шаг 1. Импортировать ruleset (30 секунд)

1. Открыть <https://github.com/bx-shef/bee2-tls-gateway/settings/rules>
2. **New ruleset** → **Import a ruleset**
3. Загрузить `.github/rulesets/main-protection.json`
4. Проверить, что **Enforcement status** = `Active`
5. **Create**

После импорта проверить **Bypass list**. Это не отдельная страница, а блок
внутри самого ruleset: **Settings → Rules → Rulesets** → кликнуть на ruleset
`main protection` → блок **Bypass list** в верхней части формы, сразу под
полями *Ruleset Name* и *Enforcement status*, выше блока *Targets*.

Там должна быть строка `Repository admin` с режимом `Always`. Если пусто —
добавить вручную: **+ Add bypass** → вкладка **Roles** → `Repository admin` →
в выпадающем списке справа от добавленной строки выбрать `Always` (вариант
`For pull requests only` слабее) → **Save changes** внизу страницы.

Репозиторий личный, поэтому владелец и есть Repository admin. Эта запись —
аварийный выход, чтобы не заблокировать самого себя.

## Шаг 2. Проверить, что защита работает

```bash
git checkout main
echo test >> README.md
git commit -am "test: прямой пуш в main"
git push origin main
```

Ожидаемый результат — отказ на стороне сервера:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
```

После проверки: `git reset --hard origin/main`.

## Что именно включено

| Правило | Тип в JSON | Что делает |
| --- | --- | --- |
| Запрет удаления ветки | `deletion` | `main` нельзя удалить |
| Запрет force-push | `non_fast_forward` | Историю нельзя переписать |
| Линейная история | `required_linear_history` | Без merge-коммитов, история читаемая |
| Только через PR | `pull_request` | Прямой пуш в `main` запрещён |
| Обязательный CI | `required_status_checks` | Мерж только при зелёном job `ci` |

Параметры PR-правила:

- `required_approving_review_count: 0` — апрув не требуется. Это осознанно:
  мейнтейнер один, а свой собственный PR на GitHub апрувить нельзя, иначе
  мержиться станет невозможно. PR остаётся обязательным — он даёт diff, историю
  обсуждения и точку, где отрабатывает CI.
- `required_review_thread_resolution: true` — все треды в PR должны быть
  разрешены до мержа.
- `dismiss_stale_reviews_on_push: true` — новый пуш сбрасывает старые апрувы
  (заработает, когда появится второй мейнтейнер).
- `allowed_merge_methods: ["squash", "rebase"]` — merge-коммиты запрещены,
  иначе они конфликтуют с требованием линейной истории.

`strict_required_status_checks_policy: true` означает, что ветка PR должна быть
актуальной относительно `main` перед мержем.

## Шаг 3. Остальные настройки репозитория (по желанию, но рекомендую)

Всё это включается кликами в Settings и не хранится в репозитории:

- **Settings → General → Pull Requests**: снять `Allow merge commits`, оставить
  `Allow squash merging` и `Allow rebase merging`; включить
  `Automatically delete head branches`.
- **Settings → Code security**: для публичного репозитория бесплатно доступны
  `Secret scanning` + `Push protection` (блокирует пуш с утёкшим ключом — для
  проекта про TLS это критично), `Dependabot alerts`,
  `Private vulnerability reporting`.
- **Settings → Actions → General**: `Fork pull request workflows from outside
  collaborators` → `Require approval for all external contributors`. Публичный
  репозиторий = любой может открыть PR с изменённым workflow.
- **Settings → Actions → General → Workflow permissions**: `Read repository
  contents permission` (в `ci.yml` уже стоит `permissions: contents: read`).
- Отдельный ruleset на теги (`target: "tag"`) — когда появятся релизы, чтобы
  тег нельзя было переставить на другой коммит.

## Как ужесточить потом

Когда в проекте появится второй мейнтейнер:

1. В `.github/rulesets/main-protection.json` поставить
   `"required_approving_review_count": 1`.
2. Убрать `bypass_actors` (или сменить `bypass_mode` на `"pull_request"`).
3. Заново импортировать ruleset, удалив старый.

Если понадобится ревью от владельцев конкретных файлов — сначала завести
`.github/CODEOWNERS`, затем выставить `"require_code_owner_review": true`.
Без файла CODEOWNERS этот параметр ни на что не влияет.

Для криптографического проекта имеет смысл также добавить правило
`{"type": "required_signatures"}` — тогда все коммиты в `main` обязаны быть
подписаны GPG/SSH. Требует настроенной подписи локально у каждого, кто пушит.

## Ограничение

Ruleset нельзя включить из CI или из агента: для этого нужен токен с правами
администратора репозитория, которого в автоматизации нет и быть не должно.
Поэтому импорт — ручной шаг, а файл в репозитории служит источником правды:
любое изменение правил проходит через PR и видно в истории.
