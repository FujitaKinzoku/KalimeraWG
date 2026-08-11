# Тестовое развёртывание EXIT сервера

Роль EXIT сначала следует запускать на чистом одноразовом VPS с Ubuntu 24.04.
Не направляйте пример inventory на рабочий EXIT сервер.

## Защитные условия

Изменение конфигурации допускается только при одновременном выполнении условий:

- `awg_adoption_mode: apply`;
- `exit_manage_awg_config: true`;
- `exit_peer_migration_policy: explicit`;
- закрытые ключи EXIT находятся в зашифрованном Vault;
- задан явный зашифрованный peer ENTRY;
- адрес и подсеть EXIT корректны.

С примерными значениями роль сохраняет существующую AWG-конфигурацию и Docker.

## Межсерверный AWG 3+

В KalimeraWG межсерверный канал использует отдельный интерфейс `awg3`, публичный
endpoint `443/UDP` по умолчанию и отдельный ключевой материал. Старый `awg0` на EXIT
останавливается только после установки и проверки AWG 3+. В UFW межсерверный
UDP-порт разрешён исключительно с постоянного публичного IPv4 ENTRY сервера.

Конфигурация AWG 3+ сначала проверяется на временном интерфейсе без занятия
рабочего UDP-порта. При изменении предыдущая версия сохраняется только в
`/root/config-backups/exit/awg3`, а проверенный кандидат устанавливается
атомарно. Закрытые ключи и PSK не выводятся.

## Совместимость со стабильным AWG 2

Для режима AWG 2 действует прежняя защищённая процедура:

1. Секретный кандидат формируется в `/run/ansible-awg0.conf.candidate` с правами `0600`.
2. Синтаксис проверяется через `awg-quick strip`, вывод подавляется.
3. Кандидат сравнивается с действующей конфигурацией.
4. При наличии изменений действующий файл копируется в `/root/config-backups/exit/awg0`.
5. Проверенный кандидат устанавливается, затем перезапускается `awg-quick@awg0`.
6. Кандидат удаляется в блоке Ansible `always`, в том числе после ошибки.

При идемпотентном повторном запуске новая резервная копия не создаётся.

## Последовательность тестирования

```bash
ansible-playbook -i inventory/test/hosts.yml playbooks/audit.yml
ansible-playbook -i inventory/test/hosts.yml playbooks/exit.yml --check --diff
ansible-playbook -i inventory/test/hosts.yml playbooks/exit.yml
ansible-playbook -i inventory/test/hosts.yml playbooks/exit.yml
```

Второй реальный запуск должен показать ноль изменений конфигурации. Задачи с
секретами используют `no_log`; не отключайте его даже для диагностики.

## Откат

Просмотрите допустимые backup непосредственно на сервере, выберите один точный
файл и передайте только его путь:

```bash
# Межсерверный AWG 3+
ansible-playbook -i inventory/test/hosts.yml playbooks/rollback-exit.yml \
  -e rollback_component=awg3 \
  -e rollback_file=/root/config-backups/exit/awg3/ПРОВЕРЕННЫЙ_ФАЙЛ

# Стабильный AWG 2
ansible-playbook -i inventory/test/hosts.yml playbooks/rollback-exit.yml \
  -e rollback_component=awg0 \
  -e rollback_file=/root/config-backups/exit/awg0/ПРОВЕРЕННЫЙ_ФАЙЛ
```

Rollback отклоняет пути вне разрешённого каталога и проверяет синтаксис AWG до восстановления.
