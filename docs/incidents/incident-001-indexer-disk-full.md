# Отчёт об инциденте INC-20261025-01

- **ID инцидента:** INC-20261025-01
- **Дата обнаружения:** 2026-10-25
- **Аналитик:** Ремигайло Е.
- **Критичность:** высокая (потеря видимости детектов)
- **Статус:** закрыт

## Краткое описание

На стенде SIEM перестали индексироваться новые события: срабатывания правил присутствовали
в локальном журнале менеджера, но не доходили до индекса и дашборда. Дашборд при загрузке
показывал ошибки создания index pattern. Причина — переполнение диска менеджера, из-за чего
Wazuh indexer (OpenSearch) перевёл индексы в режим «только чтение».

## Затронутые узлы

| Узел | IP | Роль | Признаки |
|---|---|---|---|
| wazuh-manager | 10.10.10.4 | Менеджер Wazuh + indexer + dashboard | диск `/` заполнен на 100 %, индексы read-only |

## Хронология (UTC)

| Время | Событие | Источник |
|---|---|---|
| 19:50 | Контрольная атака: правило 100100 сработало в журнале, но счётчик в индексе не рос | alerts.log vs _count |
| 19:52 | Дашборд: ошибки `disk usage exceeded flood-stage watermark … read-only-allow-delete block` | Wazuh health-check |
| 19:53 | `df -h /` → 25G/25G, 100 % | менеджер |
| 19:55 | `du` локализовал потребителя: `/var/ossec/queue/vd_updater` 13 ГБ, `/var/ossec/queue/vd` 7.2 ГБ | менеджер |
| 19:58 | Отключён модуль vulnerability-detection, вычищены базы VD → диск 27 % | менеджер |
| 20:00 | Снят `read_only_allow_delete`, перезапущен indexer → кластер green | indexer API |
| 20:01 | Повторная атака: счётчик 100100 в индексе 1 → 2, свежий timestamp | _count |

## Технические детали

Симптом в дашборде:

```
[Alerts index pattern] index [.kibana_1] blocked by:
[TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark,
 index has read-only-allow-delete block]
```

Диагностика заполнения:

```
$ df -h /
/dev/sda1  25G  25G  20K 100% /

$ sudo du -xh --max-depth=1 /var/ossec/queue | sort -rh | head
20G   /var/ossec/queue
13G   /var/ossec/queue/vd_updater   # временные файлы обновления CVE-фидов
7.2G  /var/ossec/queue/vd           # база Vulnerability Detection
```

Индексы занимали менее 1 МБ (`_cat/allocation`: `disk.indices 930.9kb`) — значит, место
съедал не поток алертов, а модуль детектирования уязвимостей, скачавший полные CVE-фиды.

## Оценка воздействия

Детектирование на уровне движка продолжало работать (алерты писались в `alerts.json`), но
**терялась видимость в дашборде и поиске** — аналитик не увидел бы новые срабатывания.
Для SOC это «слепая зона»: правила срабатывают, но до оператора не доходят.

## Первопричина

Модуль **Vulnerability Detection** включён по умолчанию в OVA и загружает полные базы CVE
(20 ГБ), а диск all-in-one OVA ограничен 25 ГБ. При превышении flood-stage watermark (95 %)
OpenSearch автоматически выставляет `index.blocks.read_only_allow_delete` — защита от порчи
данных, которая и остановила индексацию.

## Устранение

```bash
# 1. Отключить ненужный в лаборатории модуль
#    ossec.conf: <vulnerability-detection><enabled>no</enabled>
# 2. Освободить место (базы пересоздаются при повторном включении)
sudo /var/ossec/bin/wazuh-control stop
sudo rm -rf /var/ossec/queue/vd_updater /var/ossec/queue/vd
# 3. Снять блок read-only после освобождения диска
curl -sk -u admin:admin -XPUT \
  "https://localhost:9200/wazuh-alerts-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
curl -sk -u admin:admin -XPUT \
  "https://localhost:9200/.kibana*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
# 4. Перезапустить indexer и менеджер
sudo systemctl restart wazuh-indexer
sudo /var/ossec/bin/wazuh-control start
```

Результат: диск 27 %, кластер `green`, индексация возобновлена (счётчик алертов 100100 вырос
на следующей контрольной атаке).

## Рекомендации по предотвращению

1. **Мониторинг диска:** алерт при заполнении `/` > 80 % (Wazuh умеет через `command`/`df`).
2. **Правило на блокировку индексов:** детект записи в логах indexer о `read_only_allow_delete`.
3. **Отключать тяжёлые неиспользуемые модули** (Vulnerability Detection) на стендах с малым
   диском или вынести данные indexer на отдельный том.
4. **Размер диска:** для боевого all-in-one выделять ≥ 50 ГБ.

## Извлечённые уроки

Сбой был не в детектировании, а в конвейере доставки алертов — классический случай, когда
«тихая» инфраструктурная проблема создаёт слепую зону SOC. Детект работал, но без видимости
он бесполезен; поэтому за здоровьем indexer и диска нужно следить так же, как за правилами.
