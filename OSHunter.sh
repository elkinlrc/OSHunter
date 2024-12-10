#!/bin/bash

# Colores para mejorar la visualización
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # Sin color

detect_active_interface() {
  echo -e "${CYAN}[+] Detectando interfaces activas...${NC}"

  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Detectar interfaces activas en Linux
    interfaces=$(ip -o -f inet addr show | awk '{print $2, $4}')
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Detectar interfaces activas en macOS
interfaces=$(ifconfig | awk '
/^[a-z]/ { iface=$1; sub(":", "", iface) }
/inet / && $2 != "127.0.0.1" { print iface, $2 }
')




  elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
    # Detectar interfaces activas en Windows
    interfaces=$(ipconfig | findstr "IPv4" | awk '{print $NF}')
  else
    echo -e "${RED}[-] Sistema operativo no compatible.${NC}"
    exit 1
  fi

  # Mostrar todas las interfaces activas detectadas
  if [ -z "$interfaces" ]; then
    echo -e "${RED}[-] No se encontraron interfaces activas.${NC}"
    exit 1
  else
    echo -e "${GREEN}[+] Interfaces activas detectadas:${NC}"
    echo "$interfaces"
  fi

  # Seleccionar automáticamente si hay una sola interfaz
  num_interfaces=$(echo "$interfaces" | wc -l)
  if [ "$num_interfaces" -eq 1 ]; then
    selected_interface=$(echo "$interfaces" | awk '{print $1}')
    echo -e "${CYAN}[+] Se seleccionó automáticamente la interfaz: $selected_interface${NC}"
  else
    echo -e "${YELLOW}[!] Hay varias interfaces activas. Por favor selecciona una:${NC}"
    select selected_interface in $(echo "$interfaces" | awk '{print $1}'); do
      if [ -n "$selected_interface" ]; then
        echo -e "${GREEN}[+] Has seleccionado: $selected_interface${NC}"
        break
      else
        echo -e "${RED}[-] Selección no válida.${NC}"
      fi
    done
  fi

  echo -e "${CYAN}[+] Usando la interfaz: $selected_interface${NC}"
}


# Detectar interfaces activas
detect_active_interface

# Detectar rango de red (Linux y macOS)
if [[ "$OSTYPE" == "linux-gnu"*  ]]; then
  network_range=$(ip -o -f inet addr show "$selected_interface" | awk '{print $4}')
if [[ "$OSTYPE" == "darwin"* ]]; then
  # Obtener el rango de red en macOS
  network_range=$(ifconfig "$selected_interface" | awk '/inet / {print $2, $NF}' | awk '
  {
    split($1, ip, ".")
    split($2, mask, ".")
    for (i = 1; i <= 4; i++) {
      network[i] = ip[i] + 0 & mask[i] + 0
    }
    print network[1]"."network[2]"."network[3]"."network[4]"/24"
    exit
  }')


elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
  network_range=$(ipconfig | findstr "$selected_interface" | findstr "IPv4" | awk '{print $NF}')
fi

if [ -z "$network_range" ]; then
  echo -e "${RED}[-] No se pudo detectar el rango de red.${NC}"
  exit 1
fi



# Validar que se proporcione una IP o hacer un escaneo con netdiscover
#if [ -z "$1" ]; then
#  echo -e "${CYAN}[+] No se proporcionó IP. Detectando dispositivos en la red usando la tarjeta eth0...${NC}"

  # Detectar rango de red basado en eth0
#  NETWORK_RANGE=$(ip -o -f inet addr show eth0 | awk '/scope global/ {print $4}')

#  if [ -z "$NETWORK_RANGE" ]; then
#    echo -e "${RED}[-] No se pudo detectar el rango de red en eth0. Asegúrate de que la interfaz está activa.${NC}"
#    exit 1
#  fi

#  echo -e "${CYAN}[+] Rango de red detectado: ${YELLOW}$NETWORK_RANGE${NC}"
#  echo -e "${CYAN}[+] Ejecutando netdiscover en ${YELLOW}$NETWORK_RANGE${NC}..."
echo -e "${CYAN}[+] Rango de red detectado: ${YELLOW}$network_range${NC}"
  # Ejecutar netdiscover y guardar resultados
 ## netdiscover -r "$NETWORK_RANGE" -P | grep "1 " | awk '{print $1}' > discovered_hosts.txt
 echo -e "${CYAN}[+] Escaneando dispositivos en la red...${NC}"
 sudo nmap -sn "$NETWORK_RANGE" -oG - | awk '/Up$/{print $2}' > discovered_hosts.txt
  echo -e "${CYAN}[+] Dispositivos encontrados:${NC}"
  cat discovered_hosts.txt

  # Array de IPs que no deben ser escaneadas
  IGNORED_IPS=("192.168.44.1" "192.168.44.2")

  # Iterar sobre cada IP detectada
  for ip in $(cat discovered_hosts.txt); do
    # Saltar las IPs que están en la lista de excluidas
    if [[ " ${IGNORED_IPS[@]} " =~ " ${ip} " ]]; then
      echo -e "${YELLOW}[-] Ignorando $ip (en lista de exclusión).${NC}"
      continue
    fi
    # Ejecutar Nmap para detección del sistema operativo
    os_info=$(nmap -O --osscan-guess --max-os-tries 1 $ip 2>/dev/null | grep "OS details:" | cut -d':' -f2 | xargs)
    # Verificar si se detectó el sistema operativo
    if [ -z "$os_info" ]; then
       os_info="Sistema operativo no identificado"
    fi
    echo -e "\n${GREEN}#####################################################${NC}"
    echo -e "${GREEN}[+] Comenzando escaneo para la IP ${YELLOW}$ip${NC} (${CYAN}${os_info}${NC})"
    echo -e "${GREEN}#####################################################${NC}"
    $0 "$ip"
    echo -e "${GREEN}#####################################################${NC}"
    echo -e "${GREEN}[+] Finalizado escaneo para la IP ${YELLOW}$ip${NC}"
    echo -e "${GREEN}#####################################################${NC}\n"
  done
  exit 0
fi

TARGET=$1
# Ruta del script y carpeta de resultados
SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_BASE_DIR="$SCRIPT_DIR/results"
mkdir -p $RESULTS_BASE_DIR

# Subcarpeta específica para la IP objetivo
OUTPUT_DIR="$RESULTS_BASE_DIR/results_$TARGET"
mkdir -p $OUTPUT_DIR

echo "[+] Los resultados se guardarán en: $OUTPUT_DIR"

# Función para imprimir en consola y guardar en archivo
log_and_save() {
  local message=$1
  local file=$2
  echo -e "$message" | tee -a "$file"
}

# Función para verificar servicios web en los puertos proporcionados
function check_web_services() {
    local target_ip=$1
    local ports=$2

    echo -e "${CYAN}[+] Escaneando servicios web en los puertos especificados: ${YELLOW}$ports${NC}"
    for port in $(echo $ports | tr ',' ' '); do
        # Verificar si el servicio está activo en HTTP
        if curl -s --connect-timeout 3 http://$target_ip:$port > /dev/null 2>&1; then
            echo -e "${GREEN}[+] Servicio web encontrado en http://$target_ip:$port${NC}"

            # Ejecutar Nikto para buscar vulnerabilidades
            echo -e "${CYAN}[+] Ejecutando Nikto en http://$target_ip:$port...${NC}"
            nikto -h http://$target_ip:$port -output $OUTPUT_DIR/nikto_$port.txt

            echo -e "${GREEN}[+] Resultados de Nikto guardados en $OUTPUT_DIR/nikto_$port.txt${NC}"

        # Verificar si el servicio está activo en HTTPS
        elif curl -s --connect-timeout 3 https://$target_ip:$port > /dev/null 2>&1; then
            echo -e "${GREEN}[+] Servicio web encontrado en https://$target_ip:$port${NC}"

            # Ejecutar Nikto para buscar vulnerabilidades
            echo -e "${CYAN}[+] Ejecutando Nikto en https://$target_ip:$port...${NC}"
            nikto -h https://$target_ip:$port -output $OUTPUT_DIR/nikto_$port.txt

            echo -e "${GREEN}[+] Resultados de Nikto guardados en $OUTPUT_DIR/nikto_$port.txt${NC}"
        else
            echo -e "${YELLOW}[-] No se detectó un servicio web en el puerto $port.${NC}"
        fi
    done
}


echo -e "${CYAN}[+] Escaneando puertos abiertos en $TARGET...${NC}"
nmap -sS -p- --open -oN $OUTPUT_DIR/nmap.txt $TARGET
log_and_save "[+] Resultados guardados en: $OUTPUT_DIR/nmap.txt" "$OUTPUT_DIR/nmap.txt"


echo "[+] Extrayendo puertos abiertos..."
# Extraer los puertos abiertos de la salida de Nmap y guardarlos en un array
#open_ports=($(grep "open" "$OUTPUT_DIR/nmap.txt" | awk '{print $1}' | cut -d'/' -f1))
open_ports=($(grep -Eo '^[0-9]+/tcp' "$OUTPUT_DIR/nmap.txt" | cut -d'/' -f1))

# Mostrar los puertos abiertos en la consola
echo "[+] Puertos abiertos detectados: ${open_ports[@]}"

# Verificar vulnerabilidades comunes
echo -e "${CYAN}[+] Verificando vulnerabilidades comunes en $TARGET...${NC}"

VULNERABLE=0
example_ports=""
init=0 
for port in "${open_ports[@]}"; do
    echo "[*] Analizando puerto: $port"
    if [ "$init" -eq 0 ]; then
        example_ports="$port"
        init=1  # Cambiamos el estado inicial para concatenar en el siguiente ciclo
    else
        example_ports="${example_ports},$port"
    fi
    if [ "$port" == "445" ]; then
        # 1. MS17-010 (EternalBlue)
        echo -e "${CYAN}[+] Verificando MS17-010 (EternalBlue)...${NC}"
        nmap --script smb-vuln-ms17-010 -p 445 $TARGET > $OUTPUT_DIR/ms17-010.txt
        if grep -q "VULNERABLE" $OUTPUT_DIR/ms17-010.txt; then
            log_and_save "${GREEN}[+] El sistema es vulnerable a MS17-010:${NC}\n$(cat $OUTPUT_DIR/ms17-010.txt)" "$OUTPUT_DIR/ms17-010.txt"
            VULNERABLE=1
        else
            log_and_save "${RED}[-] El sistema no parece vulnerable a MS17-010.${NC}" "$OUTPUT_DIR/ms17-010.txt"
        fi
        # 3. MS08-067
        echo -e "${CYAN}[+] Verificando MS08-067...${NC}"
        nmap --script smb-vuln-ms08-067 -p 445 $TARGET > $OUTPUT_DIR/ms08-067.txt
        if grep -q "VULNERABLE" $OUTPUT_DIR/ms08-067.txt; then
            log_and_save "${GREEN}[+] El sistema es vulnerable a MS08-067:${NC}\n$(cat $OUTPUT_DIR/ms08-067.txt)" "$OUTPUT_DIR/ms08-067.txt"
            VULNERABLE=1
        else
            log_and_save "${RED}[-] El sistema no parece vulnerable a MS08-067.${NC}" "$OUTPUT_DIR/ms08-067.txt"
        fi
        # 4. SMB Signing Disabled
        echo -e "${CYAN}[+] Verificando configuración SMB (Signing Disabled)...${NC}"
        nmap --script smb-security-mode -p 445 $TARGET > $OUTPUT_DIR/smb-signing.txt
        if grep -q "message signing is disabled" $OUTPUT_DIR/smb-signing.txt; then
            VULNERABLE=1
            log_and_save "${RED}[+] SMB Signing está deshabilitado, lo cual es inseguro:${NC}\n$(cat $OUTPUT_DIR/smb-signing.txt)" "$OUTPUT_DIR/smb-signing.txt"
            # Intentar usar Responder si SMB Signing está deshabilitado
            echo -e "${CYAN}[+] Probando explotación con Responder en SMB...${NC}"
            responder -I eth0 -w -r -f > $OUTPUT_DIR/responder.log &
            sleep 10
            killall responder
            echo -e "${YELLOW}[+] Responder terminó de capturar intentos de autenticación. Revisa el archivo:${NC} $OUTPUT_DIR/responder.log"
        else
            log_and_save "${GREEN}[-] SMB Signing está habilitado.${NC}" "$OUTPUT_DIR/smb-signing.txt"
        fi
    fi

    if [ "$port" == "3389" ]; then
        # 2. CVE-2019-0708 (BlueKeep)
        echo -e "${CYAN}[+] Verificando Enumera configuraciones de cifrado en RDP ...${NC}"
        nmap --script rdp-enum-encryption -p 3389 $TARGET > $OUTPUT_DIR/bluekeep.txt
        if grep -q "VULNERABLE" $OUTPUT_DIR/bluekeep.txt; then
            log_and_save "${GREEN}[+] El sistema es vulnerable a Enumera configuraciones de cifrado en RDP :${NC}\n$(cat $OUTPUT_DIR/bluekeep.txt)" "$OUTPUT_DIR/bluekeep.txt"
            VULNERABLE=1
        else
            log_and_save "${RED}[-] El sistema no parece vulnerable a CVE-2019-0708 .${NC}" "$OUTPUT_DIR/bluekeep.txt"
        fi
        
        echo -e "${CYAN}[+] Verificando MS12-020 ...${NC}"
        nmap --script rdp-vuln-ms12-020 -p 3389 $TARGET > $OUTPUT_DIR/bluekeep.txt
        if grep -q "VULNERABLE" $OUTPUT_DIR/bluekeep.txt; then
            log_and_save "${GREEN}[+] El sistema es vulnerable a MS12-020 :${NC}\n$(cat $OUTPUT_DIR/bluekeep.txt)" "$OUTPUT_DIR/bluekeep.txt"
            VULNERABLE=1
        else
            log_and_save "${RED}[-] El sistema no parece vulnerable a MS12-020 .${NC}" "$OUTPUT_DIR/bluekeep.txt"
        fi
         # 2. CVE-2019-0708 (BlueKeep)
        echo -e "${CYAN}[+] Verificando CVE-2019-0708 (BlueKeep)...${NC}"
        nmap --script rdp-vuln-cve-2019-0708 -p 3389 $TARGET > $OUTPUT_DIR/bluekeep.txt
        if grep -q "VULNERABLE" $OUTPUT_DIR/bluekeep.txt; then
            log_and_save "${GREEN}[+] El sistema es vulnerable a CVE-2019-0708 (BlueKeep):${NC}\n$(cat $OUTPUT_DIR/bluekeep.txt)" "$OUTPUT_DIR/bluekeep.txt"
            VULNERABLE=1
        else
            log_and_save "${RED}[-] El sistema no parece vulnerable a CVE-2019-0708 (BlueKeep).${NC}" "$OUTPUT_DIR/bluekeep.txt"
        fi


    fi 
    # Ejecutar Nmap con scripts adicionales para vulnerabilidades y exploits
    echo -e "${CYAN}[+] Ejecutando escaneo avanzado en el puerto $TARGET : $port...${NC}"
    nmap -T4 $TARGET -p $port --script vuln,exploit -oN "$OUTPUT_DIR/nmap_vuln_exploit_$port.txt"
    log_and_save "[+] Resultados del escaneo avanzado guardados en: $OUTPUT_DIR/nmap_vuln_exploit_$port.txt" "$OUTPUT_DIR/nmap_vuln_exploit_$port.txt"
    

done
# Si no se encontraron vulnerabilidades básicas, preguntar para análisis masivo

  echo -e "${YELLOW}[!] No se encontraron vulnerabilidades básicas.${NC}"
  read -p "¿Deseas realizar un análisis masivo de SMB? (s/n): " smb_choice
  if [[ $smb_choice == "s" || $smb_choice == "S" ]]; then
    echo -e "${CYAN}[+] Ejecutando análisis masivo con Nmap (scripts SMB)...${NC}"
    nmap --script smb-enum* -p 139,445 $TARGET -oN $OUTPUT_DIR/smb_massive_scan.txt
    log_and_save "$(cat $OUTPUT_DIR/smb_massive_scan.txt)" "$OUTPUT_DIR/smb_massive_scan.txt"
  fi

read -p "¿Deseas realizar enumeración de directorios web con Gobuster? (s/n): " web_choice
if [[ $web_choice == "s" || $web_choice == "S" ]]; then
    echo -e "${CYAN}[+] Ejecutando enumeración de directorios web con Gobuster...${NC}"
    echo -e "gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT_DIR/gobuster_scan.txt"
    gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT_DIR/gobuster_scan.txt
    log_and_save "$(cat $OUTPUT_DIR/gobuster_scan.txt)" "$OUTPUT_DIR/gobuster_scan.txt"
fi
  
read -p "¿Deseas escanear servicios web en puertos específicos? (s/n): " web_service_choice
if [[ $web_service_choice == "s" || $web_service_choice == "S" ]]; then
    echo -e "${CYAN}[+] Por favor, especifica los puertos separados por comas (por ejemplo: $example_ports):${NC}"
    read web_ports

    # Verificar servicios web en los puertos proporcionados
    check_web_services $TARGET "$web_ports"
  fi


# Escaneo adicional para otros servicios
#echo -e "${CYAN}[+] Realizando escaneo completo con Nmap...${NC}"
#nmap -sV -A -p- -oN $OUTPUT_DIR/nmap_full.txt $TARGET
#log_and_save "$(cat $OUTPUT_DIR/nmap_full.txt)" "$OUTPUT_DIR/nmap_full.txt"





echo -e "${GREEN}[+] Todos los resultados han sido guardados en $OUTPUT_DIR.${NC}"