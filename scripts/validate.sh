#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash ./scripts/check-secrets.sh

ansible-playbook --syntax-check playbooks/audit.yml
ansible-playbook --syntax-check playbooks/site.yml
ansible-playbook --syntax-check playbooks/entry.yml
ansible-playbook --syntax-check playbooks/exit.yml
ansible-playbook --syntax-check playbooks/verify.yml
ansible-playbook --syntax-check playbooks/finalize-monitoring.yml
ansible-playbook --syntax-check playbooks/terminal.yml
ansible-playbook --syntax-check playbooks/rollback-entry.yml
ansible-playbook --syntax-check playbooks/rollback-exit.yml
ansible-playbook --syntax-check playbooks/test-failover.yml
ansible-playbook --syntax-check playbooks/test-prepare-rollback.yml
ansible-playbook --syntax-check playbooks/cleanup.yml
ansible-playbook --syntax-check tests/render-shell.yml
ansible-playbook --syntax-check tests/check-sing-box.yml
ansible-playbook --syntax-check tests/check-ansible-filters.yml

python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py'

printf 'Проверка репозитория пройдена.\n'
