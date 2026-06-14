# 🛡️ AUR Sentinel Audit

**AUR Sentinel Audit** es una herramienta gráfica y portable de auditoría defensiva para **Arch Linux y derivadas compatibles con AUR**, como **CachyOS, EndeavourOS, Garuda, Manjaro y Arch Linux puro**.

Autor: **LoboViejo 79**

---

## 📌 Objetivo del proyecto

Esta herramienta fue creada para ayudar a usuarios de Arch Linux y derivadas a revisar su exposición frente a incidentes de seguridad en AUR, especialmente campañas donde paquetes comunitarios fueron alterados, adoptados por atacantes o usados para distribuir malware.

El programa permite revisar:

- Paquetes instalados desde AUR o externos.
- Coincidencias con bases comunitarias de paquetes reportados.
- PKGBUILD con patrones potencialmente peligrosos.
- Vulnerabilidades conocidas mediante `arch-audit`.
- Conexiones activas del sistema.
- Servicios activos y habilitados.
- Puertos abiertos.
- Persistencia básica.
- Reportes profesionales en **HTML, PDF, TXT y JSON**.

---

## ⚠️ Aviso importante

Esta herramienta **no confirma por sí sola que un sistema esté infectado**.

Un resultado con ✅ significa:

```text
El paquete instalado no aparece en la base comunitaria consultada del incidente.
```

Un resultado con ❌ significa:

```text
El paquete aparece en la base consultada y debe revisarse de forma urgente.
```

El programa ayuda a detectar exposición y señales de riesgo, pero no reemplaza un análisis forense completo.

---

## 🧩 Características principales

### Interfaz gráfica portable

- Interfaz GUI con PySide6.
- Barra de progreso.
- Detección automática de distro.
- Logo visual según distro:
  - CachyOS
  - Arch Linux
  - EndeavourOS
  - Garuda
  - Manjaro
  - Linux genérico
- Botones simples:
  - Escaneo rápido
  - Escaneo completo
  - Ver herramientas
  - Fuentes del incidente
  - Generar reporte HTML/PDF
  - Abrir carpeta reportes

### Escaneo de paquetes AUR

El programa usa:

```bash
pacman -Qm
```

para detectar paquetes instalados que no pertenecen a repositorios oficiales.

Luego consulta información del paquete en AUR mediante la API pública:

```text
https://aur.archlinux.org/rpc/v5/info/<paquete>
```

Con esto intenta obtener:

- Si el paquete existe actualmente en AUR.
- Mantenedor.
- Votos.
- Popularidad.
- Última modificación.
- Estado huérfano si corresponde.

### Base comunitaria de paquetes reportados

El programa intenta actualizar una base local desde fuentes comunitarias públicas relacionadas con el incidente AUR.

Fuentes principales usadas por el programa:

```text
https://github.com/lenucksi/aur-malware-check
https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt
https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/malicious_npm_packages.txt
```

Si la descarga remota falla, usa cache local en:

```text
data/aur_malware_package_list.txt
```

### Fuentes informativas incluidas

La pestaña **Fuentes** incluye enlaces de seguimiento para consulta manual:

```text
https://discuss.cachyos.org/t/aur-compromised-1500-packages-affected-20260611/31040
https://discuss.cachyos.org/t/how-to-check-for-compromised-packages-from-the-current-aur-malware-attack/31077
https://forum.garudalinux.org/t/attack-wave-on-aur-packages/48124
https://forum.garudalinux.org/t/chaotic-aur-packages-requests-recompilation-reports/26/1238
https://github.com/lenucksi/aur-malware-check
```

---

## 🔎 Qué analiza el programa

### 1. Paquetes AUR instalados

Comando usado:

```bash
pacman -Qm
```

Muestra:

- Nombre del paquete.
- Versión instalada.
- Estado en AUR.
- Mantenedor.
- Estado frente a base del incidente.
- Riesgo.
- Puntaje.
- Motivos.

### 2. Comparación contra paquetes reportados

El programa compara cada paquete instalado contra la base comunitaria descargada.

Estados posibles:

```text
✅ No figura en base del incidente
❌ REPORTADO / INFECTADO
```

### 3. Análisis de PKGBUILD

Para cada paquete existente en AUR, descarga el PKGBUILD desde:

```text
https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=<paquete>
```

Busca patrones sospechosos como:

```text
curl | bash
wget | sh
npm install
base64 -d
chmod +x
sudo
systemctl enable
crontab
/tmp
nc
ncat
socat
python -c
bash -c
eval
exec
dd
eBPF
rootkit
descarga remota
```

Estos patrones no siempre significan infección. Sirven para marcar paquetes que deben revisarse manualmente.

### 4. CVE conocidas con arch-audit

Si está instalado, ejecuta:

```bash
arch-audit
```

Esto permite revisar vulnerabilidades conocidas en paquetes de Arch Linux.

### 5. Integridad de paquetes

En escaneo completo ejecuta:

```bash
pacman -Qkk
```

Esto revisa archivos modificados, faltantes o con advertencias de integridad.

### 6. Conexiones activas

Ejecuta:

```bash
ss -tunap
```

Muestra conexiones TCP/UDP activas y procesos asociados cuando el sistema lo permite.

### 7. Servicios systemd

Ejecuta:

```bash
systemctl list-units --type=service --state=running --no-pager
systemctl list-unit-files --state=enabled --no-pager
```

Permite ver servicios activos y servicios habilitados al inicio.

### 8. Puertos abiertos

Si `nmap` está disponible:

```bash
nmap -sT 127.0.0.1
```

Si no está disponible, usa:

```bash
ss -tulpen
```

### 9. Persistencia básica

Revisa:

```bash
crontab -l
~/.config/autostart
procesos ejecutándose desde /tmp o /var/tmp
```

---

## 📊 Reportes

El programa genera reportes en:

```text
aur_sentinel_reportes/
```

Formatos:

```text
.html
.pdf
.txt
.json
```

Desde el botón **Generar reporte HTML**, el programa permite:

- Abrir el reporte HTML.
- Abrir el reporte PDF.
- Abrir la carpeta de reportes.

---

## 🚀 Ejecución portable

No instala librerías Python globalmente.

El programa crea un entorno virtual local:

```text
.venv/
```

y allí instala las librerías desde:

```text
requirements.txt
```

### Ejecutar

```bash
unzip AUR-Sentinel-Audit-GUI-Portable-Final.zip
cd AUR-Sentinel-Audit
chmod +x autorun.sh
./autorun.sh
```

### Ejecutar versión CLI antigua

```bash
./autorun_cli.sh
```

---

## 📦 Dependencias Python

Archivo:

```text
requirements.txt
```

Contenido principal:

```text
PySide6
rich
requests
psutil
tabulate
```

---

## 🧰 Herramientas opcionales del sistema

El programa puede trabajar mejor si están instaladas:

```bash
sudo pacman -S --needed arch-audit bind-tools whois lsof nmap curl git
```

El `autorun.sh` pregunta si deseas instalarlas.

---

## 🗂️ Estructura del proyecto

```text
AUR-Sentinel-Audit/
├── aur_sentinel_gui.py
├── aur_sentinel.py
├── autorun.sh
├── autorun_gui.sh
├── autorun_cli.sh
├── requirements.txt
├── README.md
├── MODO_GUI_PORTABLE.md
├── MODO_PORTABLE.md
├── AUR-Sentinel-Audit.desktop
├── data/
├── logs/
├── reports/
├── templates/
└── aur_sentinel_reportes/
```

---

## 🔐 Seguridad del programa

AUR Sentinel Audit:

- No elimina paquetes.
- No modifica archivos del sistema.
- No desinstala nada.
- No ejecuta `curl | bash`.
- No instala herramientas sin preguntar.
- Funciona en modo lectura por defecto.
- Guarda reportes para revisión.

---

## 🧪 Flujo recomendado

1. Ejecutar `./autorun.sh`.
2. Presionar **Ver herramientas**.
3. Instalar opcionales si se desea análisis completo.
4. Presionar **Escaneo completo**.
5. Revisar pestaña **Paquetes AUR**.
6. Revisar cualquier ❌ reportado.
7. Revisar pestaña **Fuentes**.
8. Generar reporte HTML/PDF.
9. Guardar el reporte.

---

## 🧾 Interpretación rápida

### ✅ No figura en base del incidente

El paquete no aparece en la base comunitaria descargada.

### ❌ REPORTADO / INFECTADO

El paquete coincide con la base comunitaria del incidente AUR.  
Debe revisarse inmediatamente.

### Riesgo bajo

Se detectaron patrones comunes pero de bajo impacto.

### Riesgo medio/alto/crítico

El PKGBUILD contiene patrones que deben revisarse manualmente.

---

## 👤 Autor

**LoboViejo 79**

Proyecto creado para ayudar a la comunidad Linux a auditar paquetes AUR y mejorar hábitos de seguridad.

---

## 📄 Licencia sugerida

MIT License.

---

## 🤝 Contribuciones

Se aceptan mejoras como:

- Más fuentes comunitarias.
- Mejor detección de paquetes comprometidos.
- Exportación CSV.
- Verificación de hashes.
- Firma de reportes.
- Integración opcional con VirusTotal.
- Mejoras en el dashboard HTML.
- Soporte para más derivadas de Arch.


---

## Corrección de reportes y actualización de listas

La versión corregida genera automáticamente reportes al terminar el análisis:

```text
aur_sentinel_reportes/
├── reporte.html
├── reporte.pdf
├── reporte.txt
└── reporte.json
```

Desde el botón **Generar reporte HTML/PDF**, el programa permite:

- Abrir HTML.
- Abrir PDF.
- Abrir carpeta de reportes.

### Actualizar listas de paquetes reportados

Dentro de la GUI hay un botón:

```text
Actualizar listas
```

Ese botón consulta fuentes comunitarias actualizadas y guarda cache local en:

```text
data/aur_malware_package_list.txt
```

Después de actualizar listas, se recomienda ejecutar:

```text
Escaneo completo
```

### Fuentes usadas para listas y seguimiento

- GitHub: lenucksi/aur-malware-check
- Arch HedgeDoc live list usada por aur_check-v2.sh
- CachyOS forum sobre AUR compromised 1500+ packages
- CachyOS guía para revisar paquetes comprometidos
- Garuda Linux forum
- Arch Security Advisories para vulnerabilidades conocidas usadas por arch-audit


---

## Análisis de reputación de IP

AUR Sentinel Audit analiza las IP públicas detectadas en conexiones activas.

### Fuentes usadas

- **VirusTotal API v3**: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **AbuseIPDB** para reputación comunitaria y score de abuso.
- **AlienVault OTX** para pulsos comunitarios e indicadores asociados.

VirusTotal requiere header `x-apikey` para consultar objetos IP en API v3. AbuseIPDB también requiere API key. OTX se intenta consultar como fuente comunitaria y permite API key opcional.

### Configurar API keys

```bash
cp config/api_keys.example.json config/api_keys.json
nano config/api_keys.json
```

Ejemplo:

```json
{
  "virustotal_api_key": "TU_API_KEY",
  "abuseipdb_api_key": "TU_API_KEY",
  "otx_api_key": "OPCIONAL"
}
```

También puedes usar variables de entorno:

```bash
export VT_API_KEY="TU_API_KEY"
export ABUSEIPDB_API_KEY="TU_API_KEY"
export OTX_API_KEY="TU_API_KEY_OPCIONAL"
./autorun.sh
```

### Estados de conexión

```text
✅ Conexión local/confiable
✅ Sin reportes relevantes
ℹ️ Sin verificación externa completa
⚠️ Revisar
❌ Sospechosa
```

Una IP sin reportes no significa que sea 100% segura. Una IP reportada debe revisarse según proceso, puerto, destino y contexto.


---

## Reducción de falsos positivos en IP

La reputación IP usa varias señales:

- RDAP público para detectar proveedor/ASN/organización.
- VirusTotal si se configura API key.
- AbuseIPDB si se configura API key.
- AlienVault OTX como fuente comunitaria.
- Proceso local asociado a la conexión.

Para evitar falsos positivos, AUR Sentinel Audit reconoce infraestructura habitual como:

- Cloudflare
- Google
- Microsoft
- Amazon/AWS/CloudFront
- Akamai
- Fastly
- Discord
- GitHub
- Mozilla
- Apple
- Meta/Facebook

Ejemplo: muchas conexiones de Discord pasan por Cloudflare. Si OTX tiene pulses históricos pero RDAP muestra infraestructura reconocida y no hay alertas de VirusTotal/AbuseIPDB, el programa lo marca como:

```text
✅ CDN/servicio reconocido
```

Esto no significa confianza absoluta, pero evita marcar como infección conexiones normales a CDN.


---

## Guardia AUR en bandeja

La versión GUI incluye una **Guardia AUR** que queda ejecutándose en la bandeja del sistema.

Funciones:

- Monitorea `/var/log/pacman.log`.
- Detecta instalaciones o actualizaciones registradas por pacman.
- Ejecuta un escaneo rápido automáticamente.
- Notifica desde la bandeja.
- Al cerrar la ventana, el programa queda minimizado en la bandeja.

Limitación importante:

```text
El monitoreo de pacman.log detecta instalaciones después de registradas.
```

Para revisar un paquete **antes de instalarlo**, usa los wrappers incluidos:

```bash
tools/aur-guard-yay paquete
tools/aur-guard-paru paquete
```

---

## Reglas antivirus AUR

El programa analiza PKGBUILD y archivos relacionados buscando firmas del incidente AUR:

```text
npm install atomic-lockfile
pnpm install atomic-lockfile
yarn add atomic-lockfile
bun add atomic-lockfile
atomic-lockfile
npm install js-digest
pnpm add js-digest
bun add js-digest
@gsdigest/gsdigest
gsdigest
src/hooks/deps
/sys/fs/bpf/hidden_
bpftool
bpftrace
eBPF
rootkit
```

Si encuentra una firma crítica, marca el paquete como:

```text
❌ Crítico
```

Si no encuentra coincidencias, el paquete queda marcado con check verde cuando tampoco figura en la base del incidente.


---

## Icono y notificaciones del GuardTray

La Guardia AUR ahora queda en la bandeja del sistema con icono propio.

Cuando detecta una instalación o actualización en `/var/log/pacman.log`, muestra una notificación indicando que se ejecutarán controles:

- Base del incidente AUR.
- Firmas `atomic-lockfile` / `js-digest`.
- Revisión de conexiones.
- Generación automática de reporte.

Al finalizar muestra:

```text
✅ Guardia AUR: controles aprobados
```

o

```text
⚠️ Guardia AUR: revisar alertas
```

Los wrappers `aur-guard-yay` y `aur-guard-paru` también usan `notify-send` cuando está disponible para informar si la instalación pasa o queda bloqueada.


---

## Fuente oficial aur-general de Arch

Se agregó como fuente de actualización el hilo oficial de la lista `aur-general` de Arch Linux:

```text
https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/
```

Ese hilo fue usado para centralizar reportes de paquetes AUR maliciosos.  
El programa intenta extraer nombres de paquetes desde enlaces de AUR presentes en el hilo, por ejemplo:

```text
aur.archlinux.org/packages/<paquete>
aur.archlinux.org/cgit/aur.git/commit/?h=<paquete>
aur.archlinux.org/<paquete>.git
```

También consulta la lista viva mencionada por Arch:

```text
https://md.archlinux.org/s/SxbqukK6IA/download
```

Si no hay Internet, se usa la cache local:

```text
data/aur_malware_package_list.txt
```

Desde la GUI puedes usar:

```text
Actualizar listas
```

y luego ejecutar:

```text
Escaneo completo
```


---

## Instalación AUR segura interactiva

La Guardia AUR ahora puede interactuar con el usuario antes de permitir una instalación.

Desde la GUI usa:

```text
Instalar AUR seguro
```

O desde terminal:

```bash
tools/aur-guard-yay nombre-paquete
tools/aur-guard-paru nombre-paquete
```

Flujo de seguridad antes de instalar:

```text
1) Actualiza/consulta lista de paquetes AUR reportados.
2) Verifica si el paquete solicitado aparece en esa lista.
3) Descarga el PKGBUILD desde AUR.
4) Analiza firmas críticas:
   - atomic-lockfile
   - js-digest
   - @gsdigest/gsdigest
   - src/hooks/deps
   - /sys/fs/bpf/hidden_
   - bpftool / bpftrace / rootkit
5) Si todo pasa, muestra una alerta interactiva.
6) Solo si el usuario confirma, ejecuta yay/paru.
```

Si el paquete aparece reportado o el PKGBUILD contiene firmas críticas, la instalación se bloquea automáticamente.

En KDE Plasma usa `kdialog` para alertas interactivas. Si no existe, intenta usar `zenity`. Si tampoco existe, usa confirmación por terminal.


---

## Corrección NameError fuentes oficiales

Se corrigió el error:

```text
NameError: name 'ARCH_OFFICIAL_AFFECTED_LIST_URL' is not defined
```

Las fuentes oficiales/comunitarias ahora se definen antes de construir `MALWARE_DB_URLS`.

Fuentes incluidas:

- Arch affected packages live list.
- Arch aur-general official report thread.
- lenucksi/aur-malware-check.
- CachyOS paste/listas comunitarias.


---

## Popup persistente de Guardia AUR

Las alertas de Guardia AUR ahora se muestran con popup visible:

- Permanece en pantalla hasta que el usuario presione **Cerrar**.
- Se cierra automáticamente luego de **15 segundos**.
- Aparece al detectar instalación/actualización.
- Aparece al finalizar el análisis indicando si los controles pasaron o si hay alertas.

Los wrappers `aur-guard-yay` y `aur-guard-paru` también muestran avisos gráficos durante el flujo de revisión previa.


---

# 🛡️ Novedades de la versión – Guardia AUR Avanzada

## 🚀 Nuevas funciones incorporadas

Esta versión incorpora mejoras importantes enfocadas en la detección temprana de paquetes AUR comprometidos, monitoreo continuo y análisis preventivo antes de instalar software desde AUR.

### 🛡️ ¿Qué es Guardia AUR?

Guardia AUR es un sistema de protección residente que permanece ejecutándose en segundo plano y ayuda a detectar riesgos relacionados con paquetes AUR.

### Funciones principales

- Monitoreo desde la bandeja del sistema.
- Icono residente con notificaciones.
- Popup interactivo visible durante 15 segundos o hasta que el usuario lo cierre.
- Escaneo automático cuando detecta instalaciones o actualizaciones.
- Generación automática de reportes.
- Verificación de paquetes reportados por la comunidad.
- Revisión automática de PKGBUILD.

---

## 🔐 Cómo funciona Guardia AUR

Cuando el usuario solicita instalar un paquete utilizando el modo seguro:

```text
1. Consulta listas de paquetes reportados.
2. Consulta fuentes oficiales y comunitarias.
3. Descarga el PKGBUILD.
4. Analiza el contenido completo.
5. Busca firmas críticas conocidas.
6. Evalúa el riesgo.
7. Solicita confirmación del usuario.
8. Permite o bloquea la instalación.
```

Si detecta un paquete reportado o una firma crítica, la instalación es bloqueada automáticamente.

---

## 🔍 Fuentes utilizadas para detección

### Fuentes oficiales

- Arch Linux aur-general
- Arch Linux affected packages list
- AUR RPC API
- Arch Audit

### Fuentes comunitarias

- aur-malware-check
- CachyOS Security Discussions
- Garuda Linux Security Reports
- Reportes públicos de la comunidad

Las listas pueden actualizarse desde el propio programa mediante:

```text
Actualizar listas
```

---

## 🦠 Firmas críticas detectadas

```text
atomic-lockfile
js-digest
@gsdigest/gsdigest
src/hooks/deps
bpftool
bpftrace
eBPF
rootkit
curl | bash
wget | sh
base64 -d
eval
exec
```

---

## ⚠️ ADVERTENCIA LEGAL

> [!WARNING]
> Esta herramienta utiliza análisis heurístico, listas comunitarias, firmas conocidas y fuentes externas. Ningún sistema de detección puede garantizar una precisión absoluta.

### Posibles falsos positivos

- Un paquete legítimo podría ser marcado como sospechoso.
- Una IP legítima podría aparecer reportada en una fuente comunitaria.
- Una conexión legítima podría compartir infraestructura con servicios previamente reportados.
- Un paquete no reportado NO significa que sea completamente seguro.

### Posibles falsos negativos

- Pueden existir amenazas nuevas aún no reportadas.
- Pueden existir modificaciones recientes todavía no incluidas en las listas utilizadas.
- Un atacante puede utilizar técnicas no contempladas por las reglas actuales.

### Exención de responsabilidad

> [!CAUTION]
> El software se distribuye "TAL CUAL" ("AS IS"), sin garantías de ningún tipo.

El autor:

**LoboViejo79**

no se responsabiliza por:

- Daños directos o indirectos.
- Pérdida de información.
- Fallos del sistema.
- Decisiones tomadas a partir de los resultados obtenidos.
- Falsos positivos.
- Falsos negativos.
- Interrupciones del servicio.

La decisión final sobre instalar, eliminar o mantener software corresponde exclusivamente al usuario.

Se recomienda verificar manualmente cualquier hallazgo antes de tomar decisiones en entornos de producción.

---

© LoboViejo79 – AUR Sentinel Audit
