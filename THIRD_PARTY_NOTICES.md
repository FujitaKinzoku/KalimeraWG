# Уведомления о сторонних компонентах

## amneziawg-installer

Часть архитектуры основана на документации каскада из
[bivlked/amneziawg-installer](https://github.com/bivlked/amneziawg-installer).
Для воспроизводимости закреплён commit `2c86966f59d54c0fd0bcf66639c537558a1a0c25`.

Ниже без изменений приведён обязательный оригинальный текст лицензии MIT:

MIT License

Copyright (c) 2025-2026 Ivan Bondarev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## amneziawg-go и amneziawg-tools

KalimeraWG загружает и собирает закреплённые upstream-релизы
[amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) и
[amnezia-vpn/amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools).
Их исходники не включаются в репозиторий. Применимые лицензионные уведомления
остаются в загружаемых деревьях исходников; происхождение и точные ревизии
зафиксированы в `docs/upstream.md`.

## ble.sh

KalimeraWG загружает закреплённую ревизию
[akinomyoga/ble.sh](https://github.com/akinomyoga/ble.sh) для интерактивной
подсветки и дополнения Bash. Исходники не включаются в этот репозиторий;
лицензия BSD 3-Clause и уведомления правообладателей сохраняются в
устанавливаемом upstream-дереве. Точная ревизия указана в `docs/upstream.md`.
