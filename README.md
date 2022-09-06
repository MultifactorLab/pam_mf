# pam_mf
Данный PAM модуль создан для проверки второго фактора, используя RADIUS протокол. 
Во многом схема работы модуля похожа на winlogon. 
Сначала выбирается radius сервер, для этого используется Status-Server (12) запрос. 
Дальнейшая сессия происходит с первым ответившим сервером. 
Также данный модуль позволяет настраивать свое поведения в зависимости от ситуации и с учетом того сервиса, 
который вызвал модуль.
Поодробности см. pam_mf.conf и example.txt

## Перед сборкой нужно установить
- Debian based Systems:
$ sudo apt-get install autoconf libtool libpam-dev libssl-dev make
- RHEL based systems:
$ sudo yum install autoconf libtool pam-devel openssl-devel

## Сборка
# $ chmod a+x ./configure
# $ ./configure --with-pamdir=<pam_modules_dir>
# <pam_modules_dir> - путь куда будет установлен pam модуль, обычно это usr/lib/security, но могут быть отличия.
# $ make

## Установка
$ sudo make install

## Настройка
После установки отредактируйте файл конфигурации /etc/pam_mf.conf. Далее можно добавлять вызов модуля в ваш pam стек.

Строка в pam стеке будет иметь примерно такой вид:
auth     required   pam_mf.so [config]
[config] - расположение конфиг файла. По умолчанию: /etc/pam_mf.conf
