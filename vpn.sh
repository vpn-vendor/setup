#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# Скрипт автонастройки VPN-раздачи интернета в локальную сеть
# ----------------------------------------------------------------------------
# Версия: 4.0.0 
# ----------------------------------------------------------------------------
# ОПИСАНИЕ:
#  1) Поддерживает Ubuntu (20.04, 22.04, 24.04) и Linux Mint
#  2) Не трогает systemd-resolved 
#  3) Делает резервные копии netplan-конфигов для возможности отката
#  4) Есть логирование в папку ~/log
#  5) Мониторинг VPN
# ----------------------------------------------------------------------------

# ============================================================================
# ============================= НАСТРОЙКИ ====================================
# ============================================================================

SCRIPT_VERSION="4.0.0"

# Папка для логов
LOG_BASE_DIR="$HOME/log"
LOG_SETUP_DIR="$LOG_BASE_DIR/vpn-setup"
LOG_MONITOR_DIR="$LOG_BASE_DIR/vpn-monitor"

# Дней хранения логов (для чистки)
LOG_RETENTION_DAYS=7

# Папка для резервных конфигов netplan
NETPLAN_BACKUP_DIR="/etc/netplan/backup_$(date +%Y%m%d_%H%M%S)"

# Файл основного netplan
NETPLAN_MAIN_FILE="/etc/netplan/01-my-network-setup.yaml"

# Интервал мониторинга (в секундах)
VPN_MONITOR_INTERVAL="60"

# ============================================================================
# ==================== 1. ЛОГИРОВАНИЕ =======================
# ============================================================================

# ----------------------------------------------------------------------------
# Создания ежедневного файла лога для сбора ошибок
# ----------------------------------------------------------------------------
get_today_logfile() {
  local log_subdir="$1"  
  local logdir="${LOG_BASE_DIR}/${log_subdir}"
  mkdir -p "$logdir"

  # Удаление старых логов
  find "$logdir" -type f -mtime +$LOG_RETENTION_DAYS -exec rm -f {} \; 2>/dev/null

  # Имя лога
  local logfile="${logdir}/${log_subdir}-$(date +%Y-%m-%d).log"
  echo "$logfile"
}

# ----------------------------------------------------------------------------
# Запись строк в лог
# ----------------------------------------------------------------------------
log_message() {
  local log_subdir="$1"
  local level="$2"
  local message="$3"

  local logfile
  logfile="$(get_today_logfile "$log_subdir")"

  local timestamp
  timestamp="$(date "+%Y-%m-%d %H:%M:%S")"

  echo "[$timestamp] [$level] $message" | tee -a "$logfile"
}

# Логика создания строчки для лога
log_setup_info()    { log_message "vpn-setup" "INFO" "$1"; }
log_setup_error()   { log_message "vpn-setup" "ERROR" "$1"; }
log_monitor_info()  { log_message "vpn-monitor" "INFO" "$1"; }
log_monitor_error() { log_message "vpn-monitor" "ERROR" "$1"; }

# ----------------------------------------------------------------------------
# АНИМАЦИЯ теста
# ----------------------------------------------------------------------------
animate_check() {
  local text="$1"
  local -i i
  for ((i=0; i<${#text}; i++)); do
    echo -n "${text:$i:1}"
    sleep 0.02
  done
  echo
}

# ============================================================================
# ========== 2. ФУНКЦИИ ДЛЯ СОХРАНЕНИЯ/ВОССТАНОВЛЕНИЯ NETPLAN-КОНФИГОВ ========
# ============================================================================

# ----------------------------------------------------------------------------
# Сохраняем все имеющиеся бэкапы в папку
# ----------------------------------------------------------------------------
backup_netplan_configs() {
  if [ ! -d "$NETPLAN_BACKUP_DIR" ]; then
    mkdir -p "$NETPLAN_BACKUP_DIR"
    cp -a /etc/netplan/*.yaml "$NETPLAN_BACKUP_DIR" 2>/dev/null || true
    log_setup_info "Бэкап netplan сохранен в: $NETPLAN_BACKUP_DIR"
  else
    log_setup_info "Папка бэкапа уже существует: $NETPLAN_BACKUP_DIR"
  fi
}

# ----------------------------------------------------------------------------
# Восстанавление .yaml-файлов из бэкапа
# ----------------------------------------------------------------------------
restore_netplan_configs() {
  if [ -d "$NETPLAN_BACKUP_DIR" ]; then
    # Удаляем текущие .yaml
    rm -f /etc/netplan/*.yaml
    # Копируем обратно
    cp -a "$NETPLAN_BACKUP_DIR"/*.yaml /etc/netplan/ 2>/dev/null || true
    log_setup_info "Восстановлен бэкап netplan из: $NETPLAN_BACKUP_DIR"
  else
    log_setup_error "Папка с бэкапом netplan не найдена: $NETPLAN_BACKUP_DIR"
    echo "Папка с бэкапом не найдена. Откат невозможен."
  fi
}

# ----------------------------------------------------------------------------
# Удаляем наш новый файл netplan (при откате).
# ----------------------------------------------------------------------------
remove_our_netplan_file() {
  if [ -f "$NETPLAN_MAIN_FILE" ]; then
    rm -f "$NETPLAN_MAIN_FILE"
    log_setup_info "Удалён основной netplan-файл: $NETPLAN_MAIN_FILE"
  fi
}

# ============================================================================
# ============= 3. ПРОВЕРКА ИНТЕРНЕТА ==================
# ============================================================================

check_internet_with_animation() {
  echo ""
  echo "Начинается проверка доступа к Интернету (DNS + HTTP)..."
  echo ""

  local test_domain="www.google.com"
  local fallback_ip="8.8.8.8"
  local res_code

  # "Анимация"
  animate_check "Проверяю доступ к ${test_domain} ..."
  
  # curl для проверки HTTP
  res_code=$(curl -s -o /dev/null -w "%{http_code}" "http://${test_domain}" --max-time 5)
  if [ "$res_code" == "200" ]; then
    echo "Ответ от ${test_domain} = OK (код $res_code)"
    log_setup_info "Проверка google.com успешно. Код: $res_code"
    return 0
  else
    echo "Не удалось получить корректный код от ${test_domain}. Код: $res_code"
    log_setup_error "Не получили код 200 от google.com (получили $res_code)"
    
    # Проверяем 8.8.8.8 (ping)
    animate_check "Проверяем доступ к ${fallback_ip} (ping)..."
    if ping -c1 -W2 "$fallback_ip" &>/dev/null; then
      echo "ICMP-ответ от $fallback_ip получен, интернет есть, но проблемы вероятнее всего с DNS"
      log_setup_error "ВНИМЕНИЕ!!! Проблемы с DNS, но интернет пингуется."
      return 1
    else
      echo "Нет ответа от $fallback_ip — возможно, интернет недоступен."
      log_setup_error "Хуйня: ни google.com, ни 8.8.8.8 не доступны :("
      return 2
    fi
  fi
}

# ============================================================================
# ======================== 4. НАСТРОЙКА СЕТЕЙ ================================
# ============================================================================

# ----------------------------------------------------------------------------
# Запрос сетевых параметров + создание netplan
# ----------------------------------------------------------------------------
configure_network() {
  echo ""
  echo "ПЕРЕД НАСТРОЙКОЙ СЕТИ будут созданы БЭКАПЫ текущие netplan."
  backup_netplan_configs
  
  # Создание своего netplan файла
  remove_our_netplan_file

  echo ""
  echo "Укажи ВХОДЯЩИЙ (WAN) интерфейс (например, eth0/enp2s0) - internet"
  read -p "Введи имя интерфейса: " input_interface

  echo "Укажи ВЫХОДЯЩИЙ (LAN) интерфейс (например, eth1/enp3s0) - локальная сеть"
  read -p "Введи имя интерфейса: " output_interface

  # Проверка на долбоеба
  if [ "$input_interface" == "$output_interface" ]; then
    echo "Ошибка: Входящий и исходящий интерфейсы совпадают!"
    log_setup_error "Входящий и исходящий интерфейсы одинаковы ($input_interface). Настройка отменена."
    return 1
  fi

  echo ""
  echo "Будет назначен IP для локальной сети. По умолчанию 192.168.1.1"
  read -p "Введи локальный IP (192.168.X.1), либо оставь пустым для 192.168.1.1: " local_ip

  if [ -z "$local_ip" ]; then
    local_ip="192.168.1.1"
  fi

  # Проверка на невдупленыша
  if [[ ! "$local_ip" =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
    echo "Неправильный формат IP. Ожидается 192.168.X.1"
    log_setup_error "Неправильный формат IP: $local_ip"
    return 1
  fi

  echo ""
  echo "Выбери способ получения IP на ВХОДЯЩЕМ-интерфейсе:"
  echo "1) Получать интернет по DHCP от провайдера или другого сервера"
  echo "2) Статический IP по данным от провайдера"
  echo "Выбирай №1 если не уверен или не знаешь"
  read -p "Введи 1 или 2: " wan_choice

  # НАСТРОЙКА NETPLAN
  local wan_config=""
  local lan_config=""
  lan_config="      dhcp4: false
      addresses: [$local_ip/24]
      nameservers:
        addresses: [1.1.1.1, 1.0.0.1]
      optional: true"

  if [ "$wan_choice" == "1" ]; then
    # WAN = DHCP
    wan_config="      dhcp4: true"
  elif [ "$wan_choice" == "2" ]; then
    echo "Введи IP-адрес (например, 100.100.50.50):"
    read -p "IP: " wan_ip
    echo "Введи маску сети, вставь значение "24" если не знаешь(уточняй у провайдера):"
    read -p "Маска (24): " wan_cidr
    [ -z "$wan_cidr" ] && wan_cidr="24"
    echo "Введи шлюз:"
    read -p "Шлюз: " wan_gw
    echo "Введи DNS1:"
    read -p "DNS1: " wan_dns1
    echo "Введи DNS2:"
    read -p "DNS2: " wan_dns2

    wan_config="      dhcp4: false
      addresses: [$wan_ip/$wan_cidr]
      gateway4: $wan_gw
      nameservers:
        addresses: [$wan_dns1, $wan_dns2]"
  else
    echo "Неправильный ввод."
    log_setup_error "WAN Choice: $wan_choice (не 1 и не 2)"
    return 1
  fi

  # ----------------------------------------------------------------------------
  # Создаём netplan
  # ----------------------------------------------------------------------------
  cat <<EOF | sudo tee "$NETPLAN_MAIN_FILE" > /dev/null
network:
  version: 2
  renderer: networkd
  ethernets:
    $input_interface:
$wan_config
    $output_interface:
$lan_config
EOF

  # Применяем netplan
  echo ""
  echo "Применяем netplan..."
  sudo netplan apply
  sleep 5

  # Проверка интернета
  check_internet_with_animation
  local check_result=$?

  if [ "$check_result" -eq 0 ]; then
    echo "Сетевая настройка успешно применена, интернет ЕСТЬ."
    log_setup_info "Сетевая настройка применена, интернет ЕСТЬ."
  else
    echo "Обнаружена проблема с доступом в интернет!"
    log_setup_error "После netplan apply пропал доступ к интернету (код=$check_result). Попытка отката..."

    # Откатимся
    remove_our_netplan_file
    restore_netplan_configs
    sudo netplan apply
    log_setup_info "Выполнен откат netplan."

    # Проверка интернета после отката
    check_internet_with_animation
    echo "Настройки сети откатились УСПЕШНО."
    return 1
  fi

  # 
  # Настройка DHCP сервера (dnsmasq)
  echo ""
  echo "Устанавливаем и запускаем dnsmasq для локальной сети..."
  sudo apt-get update && sudo apt-get install -y dnsmasq

  # Конфиг dnsmasq (минимальный)
  sudo bash -c "cat <<EOD > /etc/dnsmasq.conf
dhcp-authoritative
domain=office.net
listen-address=127.0.0.1,$local_ip
dhcp-range=${local_ip%.*}.2,${local_ip%.*}.254,255.255.255.0,12h
server=1.1.1.1
server=1.0.0.1
cache-size=10000
EOD"

  sudo systemctl enable dnsmasq
  sudo systemctl restart dnsmasq

  # +net.ipv4.ip_forward
  echo "Включаем ip_forward..."
  sudo sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
  sudo sysctl -p

  echo "Настройка сети (LAN + DHCP) - ГОТОВО."
  log_setup_info "Сеть настроена, ВХОД(LAN)=$output_interface ($local_ip), ВЫХОД(WAN)=$input_interface"
  return 0
}

# ============================================================================
# ============== 5. УСТАНОВКА OpenVPN/WireGuard + ВЕБ-ИНТЕРФЕЙС ==============
# ============================================================================

install_vpn_and_web() {
  echo ""
  echo "Устанавливка пакетов + обновление"
  sudo apt-get update
  sudo apt-get install -y \
       htop net-tools mtr network-manager wireguard openvpn apache2 php git \
       iptables-persistent openssh-server resolvconf speedtest-cli nload \
       libapache2-mod-php wget ufw openvswitch-switch

  # Запускаем и активируем openvswitch
  sudo systemctl start openvswitch-switch
  sudo systemctl enable openvswitch-switch

  # Настраиваем SSH
  echo "Открываем доступ по SSH (порт 22), разрешаем RootLogin..."
  sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
  sudo systemctl restart ssh
  sudo ufw allow OpenSSH

  # Iptables (MASQUERADE для tun0)
  sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
  sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null

  # Устанавливаем сайт
  echo "Устанавливаю веб-интерфейс..."
  sudo rm -rf /var/www
  sudo git clone https://github.com/Rostarc/VPN-Web-Installer.git /var/www/html

  sudo chown -R www-data:www-data /var/www/html
  sudo chmod -R 755 /var/www/html

  # ВЕБ-ДОСТУП (разрешаем доступ только из 192.168.0.0)
  sudo bash -c "cat <<EOD > /var/www/html/.htaccess
<RequireAll>
  Require ip 192.168
</RequireAll>
EOD"

  # Разрешаем override
  sudo a2enmod rewrite
  sudo systemctl restart apache2

  # Добавляем sudo-права для www-data
  sudo bash -c 'cat <<EOD >> /etc/sudoers
www-data ALL=(ALL) NOPASSWD: ALL
EOD'

  echo ""
  echo "VPN и веб-интерфейс установлены. Можно настроить конфиги через сайт."
  echo "Чтобы зайти в веб-интерфейс вводи этот адрес: http://$local_ip"
  log_setup_info "Выполнена полная установка: OpenVPN + WireGuard + веб-интерфейс."
}

# ============================================================================
# ==================== 6. УДАЛЕНИЕ НАСТРОЕК И ОТКАТ ==========================
# ============================================================================

remove_all_settings() {
  echo "Удаляем OpenVPN, WireGuard, веб-сайт..."

  # Остановка служб
  sudo systemctl stop openvpn@client1.service wg-quick@tun0.service dnsmasq.service apache2.service || true
  sudo systemctl disable openvpn@client1.service || true
  sudo systemctl disable wg-quick@tun0.service || true

  # Удаляем конфиги
  sudo rm -rf /etc/openvpn
  sudo rm -rf /etc/wireguard

  # Удаляем пакеты
  sudo apt-get purge -y wireguard openvpn dnsmasq
  sudo apt-get autoremove -y

  # Удаляем сайт
  sudo rm -rf /var/www/html

  # Удаляем конфиги iptables
  sudo iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true
  sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null

  # Откат netplan
  remove_our_netplan_file
  restore_netplan_configs
  sudo netplan apply || true

  # Удаление мониторинга VPN
  sudo systemctl disable vpn-monitor.service >/dev/null 2>&1 || true
  sudo systemctl stop vpn-monitor.service >/dev/null 2>&1 || true
  sudo rm -f /etc/systemd/system/vpn-monitor.service
  sudo systemctl disable vpn-monitor.timer >/dev/null 2>&1 || true
  sudo systemctl stop vpn-monitor.timer >/dev/null 2>&1 || true
  sudo rm -f /etc/systemd/system/vpn-monitor.timer
  sudo rm -f /usr/local/bin/vpn-monitor.sh

  echo "Удаление завершено. Все настройки и пакеты (VPN, dnsmasq) убраны, netplan откатился."
  log_setup_info "Выполнено удаление и откат."
}

# ============================================================================
# ============= 7. ДОПОЛНИТЕЛЬНЫЙ ПУНКТ: ЧИСТОЕ ВОССТАНОВЛЕНИЕ NETPLAN ========
# ============================================================================

restore_only_netplan() {
  echo "Восстанавливаем только netplan из бэкапа..."
  remove_our_netplan_file
  restore_netplan_configs
  sudo netplan apply
  log_setup_info "Произвели ручное восстановление netplan из бэкапа."
  echo "Восстановление netplan завершено."
}

# ============================================================================
# ============= 8. МОНИТОРИНГ VPN (СКРИПТЫ) ==================
# ============================================================================

create_vpn_monitor_script() {
  sudo bash -c "cat <<'EOF' > /usr/local/bin/vpn-monitor.sh
#!/usr/bin/env bash

LOG_DIR=\"$HOME/log/vpn-monitor\"
mkdir -p \"\$LOG_DIR\"
# Удалим старые логи (старше 7 дней)
find \"\$LOG_DIR\" -type f -mtime +7 -exec rm -f {} \\; 2>/dev/null

LOG_FILE=\"\$LOG_DIR/vpn-monitor-\$(date +%Y-%m-%d).log\"

timestamp() {
  date +\"%Y-%m-%d %H:%M:%S\"
}

write_log() {
  local level=\"\$1\"
  local message=\"\$2\"
  echo \"[\$(timestamp)] [\$level] \$message\" >> \"\$LOG_FILE\"
}

# Проверяем состояние OpenVPN
if systemctl is-active --quiet openvpn@client1.service; then
  write_log \"INFO\" \"OpenVPN (client1) активен.\"
else
  write_log \"ERROR\" \"OpenVPN (client1) не активен! Пытаюсь перезапустить...\"
  systemctl restart openvpn@client1.service
  sleep 5
  if systemctl is-active --quiet openvpn@client1.service; then
    write_log \"INFO\" \"OpenVPN (client1) успешно перезапущен.\"
  else
    write_log \"ERROR\" \"OpenVPN (client1) не удалось перезапустить.\"
  fi
fi

# Проверяем состояние WireGuard (wg-quick@tun0)
if systemctl is-active --quiet wg-quick@tun0.service; then
  write_log \"INFO\" \"WireGuard (tun0) активен.\"
else
  write_log \"ERROR\" \"WireGuard (tun0) не активен! Пытаюсь перезапустить...\"
  systemctl restart wg-quick@tun0.service
  sleep 5
  if systemctl is-active --quiet wg-quick@tun0.service; then
    write_log \"INFO\" \"WireGuard (tun0) успешно перезапущен.\"
  else
    write_log \"ERROR\" \"WireGuard (tun0) не удалось перезапустить.\"
  fi
fi

# Проверяем ping до google.com, чтобы понять состояние DNS/интернета
PING_COUNT=5
PING_OUTPUT=\$(ping -c \$PING_COUNT www.google.com 2>/dev/null)
if [ \$? -eq 0 ]; then
  # Парсинг статы времени
  AVG=\$(echo \"\$PING_OUTPUT\" | grep \"rtt\" | awk -F'/' '{print \$5}')
  if [ -n \"\$AVG\" ]; then
    write_log \"INFO\" \"google.com доступен, средний пинг ~ \${AVG}мс\"
    # Проверка на высокое значение
    local THRESHOLD=50.0
    # Можно подставить динамическое отслеживание
    comp=\$(awk -v a=\"\$AVG\" -v b=\"\$THRESHOLD\" 'BEGIN{print (a > b) ? 1 : 0}')
    if [ \$comp -eq 1 ]; then
      write_log \"INFO\" \"ПОВЫШЕНИЕ ПИНГА: Средний пинг \$AVG мс превысил порог \$THRESHOLD мс\"
    fi
  else
    write_log \"INFO\" \"google.com пингуется, но не удалось считать средний пинг.\"
  fi
else
  write_log \"ERROR\" \"google.com не пингуется! Возможно проблема с DNS или интернетом.\"
fi

EOF"

  sudo chmod +x /usr/local/bin/vpn-monitor.sh
}

# ----------------------------------------------------------------------------
# Создаём systemd unit + timer
# ----------------------------------------------------------------------------
create_vpn_monitor_systemd_units() {
  sudo bash -c "cat <<EOF > /etc/systemd/system/vpn-monitor.service
[Unit]
Description=VPN Monitor Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-monitor.sh
RemainAfterExit=true
EOF"

  sudo bash -c "cat <<EOF > /etc/systemd/system/vpn-monitor.timer
[Unit]
Description=Run vpn-monitor.service every ${VPN_MONITOR_INTERVAL} seconds

[Timer]
OnUnitActiveSec=${VPN_MONITOR_INTERVAL}
AccuracySec=1s
Unit=vpn-monitor.service

[Install]
WantedBy=multi-user.target
EOF"
}

enable_vpn_monitor() {
  create_vpn_monitor_script
  create_vpn_monitor_systemd_units
  sudo systemctl daemon-reload
  sudo systemctl enable vpn-monitor.timer
  sudo systemctl start vpn-monitor.timer
  log_setup_info "Включён таймер мониторинга VPN каждые ${VPN_MONITOR_INTERVAL} сек."
  echo "Система мониторинга VPN запущена."
}

# ============================================================================
# ============================ 9. МЕНЮШКА ====================================
# ============================================================================

main_menu() {
  clear
  echo "============================================================="
  echo " Скрипт автонастройки сервера для VPN + ВЕБ-САЙТ (версия $SCRIPT_VERSION)"
  echo "============================================================="
  echo ""
  echo "Выбери опцию (вписав цифру и нажав Enter):"
  echo "1) Полная настройка сервера (Сеть + VPN + Веб-интерфейс + Мониторинг)"
  echo "2) Настроить только сети (DHCP, netplan)"
  echo "3) Установка веб-интерфейса (VPN, сайт) БЕЗ сети"
  echo "4) Удалить все настройки (включая VPN, dnsmasq) и откат netplan"
  echo "5) Восстановить netplan из бэкапа (без удаления пакетов)"
  echo ""

  read -p "Ваш выбор [1/2/3/4/5]: " choice

  case "$choice" in
    1)
      # Полная настройка
      configure_network
      if [ $? -eq 0 ]; then
        install_vpn_and_web
        enable_vpn_monitor
      fi
      ;;
    2)
      # Только сети
      configure_network
      ;;
    3)
      # Только веб-интерфейс + VPN
      install_vpn_and_web
      ;;
    4)
      # Удаление
      remove_all_settings
      ;;
    5)
      # Восстановить netplan
      restore_only_netplan
      ;;
    *)
      echo "Некорректный ввод."
      ;;
  esac
}

# Запуск меню
main_menu
