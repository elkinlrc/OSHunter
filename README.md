# OSHunter

OSHunter es un script en Bash diseñado para escanear vulnerabilidades en dispositivos dentro de una red local. Es una herramienta educativa ideal para aquellos que se inician en el hacking ético y desean comprender cómo identificar y analizar posibles vulnerabilidades en sistemas.

## 🚀Características🚀

- **Detección de dispositivos en la red:** Utiliza `netdiscover` para identificar dispositivos activos.
- **Escaneo de puertos abiertos:** Emplea `nmap` para detectar puertos abiertos y servicios asociados.
- **Identificación de vulnerabilidades conocidas:** Verifica la presencia de vulnerabilidades como MS17-010 (EternalBlue), MS08-067 y CVE-2019-0708 (BlueKeep).
- **Análisis de servicios web:** Utiliza `Nikto` para detectar configuraciones inseguras y posibles fallos en servidores web.
- **Enumeración de directorios web:** Ofrece la opción de usar `Gobuster` para descubrir directorios y archivos ocultos en servidores web.
- **Resultados organizados:** Guarda los resultados en directorios específicos para cada dispositivo analizado, facilitando su revisión.

## 📋 Requisitos de Instalación

Antes de ejecutar OSHunter, asegúrate de tener instaladas las siguientes herramientas en tu sistema:

- **Nmap:** Herramienta para escaneo de puertos y detección de servicios.
- **Netdiscover:** Utilidad para descubrir dispositivos en la red.
- **Nikto:** Escáner de servidores web para detectar vulnerabilidades.
- **Gobuster:** Herramienta para enumeración de directorios y archivos en servidores web.
- **Responder:** Herramienta para analizar y responder a solicitudes en redes, útil en pruebas de seguridad relacionadas con SMB.

### Instalación de Herramientas en Sistemas Basados en Debian/Ubuntu

```bash
sudo apt update
sudo apt install nmap netdiscover nikto gobuster responder
```
⚠️ Nota Legal

Este script está destinado únicamente a fines educativos y debe utilizarse en entornos donde tengas autorización explícita para realizar pruebas de seguridad. El uso no autorizado de OSHunter puede ser ilegal y está en contra de las prácticas de hacking ético. Los autores no se responsabilizan por el uso indebido de esta herramienta.

🛡️ Próximamente

Compatibilidad total con macOS.
Automatización adicional para la instalación de herramientas en diferentes sistemas operativos.
Mejoras en la detección de vulnerabilidades y servicios.

📚 Contribuciones

¡Las contribuciones son bienvenidas! Si deseas colaborar, por favor, realiza un fork del repositorio, crea una nueva rama con tus mejoras y envía un pull request para su revisión.



