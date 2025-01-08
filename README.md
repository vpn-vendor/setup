# Описание
Этот скрипт выполняет автоматическую проверку версии linux и начинает легкую автоматическую настройку сервера для раздачи vpn-конфигурации (OpenVPN/WuireGuard) в локальную сеть (по дэфолту 192.168.1.1).

На данной момент версии скрипт работает только на:
   - Linux mint
     
Пока что дорабатывается возможность корректной установки для Ubuntu 20.04/22.04/24.04 (в разработке)

Скрипт для версий Ubuntu 20.04/22.04/24.04 можно найти по ссылке - https://github.com/Rostarc/VPN-Setup-Script


# Программы
Скрипт выполняет автоматическое обновление системы и установка таких программ:

   - htop
   - net-tools
   - dnsmasq/isc-dhcp-server
   - network-manager
   - speedtest-cli
   - nload
   - mtr
   - wireguard
   - openvpn
   - apache2
   - git
   - iptables-persistent
   - openssh-server
   - resolvconf
   - php
   - Libapache2-mod-php
   - Wget
   - Openvswitch-switch


# Установка
Команда для установки и запуска скрипта
```bash
wget https://raw.githubusercontent.com/Rostarc/setup/main/vpn.sh -O vpn.sh && sudo bash vpn.sh
```

# Контакты и сотрудничество
Всегда готов обсудить условия для работы с вами и вашими решениями. 
Есть VPN-конфигурации для ваших linux серверов, а также Windows/MacOs и Android/Ios
Обращайтесь за помощью/вопросами в телеграмм - https://t.me/vpn_vendor 
