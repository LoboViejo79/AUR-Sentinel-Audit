# 🛡️ AUR Sentinel Audit - Modo Portable

Esta versión incluye un lanzador **autorun.sh** que permite ejecutar el programa sin instalar librerías globalmente.

## Ejecutar en modo portable

```bash
unzip AUR-Sentinel-Audit-Portable.zip
cd AUR-Sentinel-Audit
chmod +x autorun.sh
./autorun.sh
```

## Qué hace autorun.sh

- Verifica que exista `python3`.
- Verifica que exista `requirements.txt`.
- Crea un entorno virtual local `.venv`.
- Instala las librerías dentro de `.venv`.
- Pregunta si deseas instalar herramientas opcionales del sistema.
- Ejecuta `aur_sentinel.py`.
- Guarda logs en la carpeta `logs/`.

## No instala globalmente

Las librerías Python quedan dentro de:

```text
.venv/
```

Puedes borrar todo simplemente eliminando la carpeta del programa.

## Limpieza

```bash
rm -rf .venv logs aur_sentinel_reportes
```

## Ejecutar nuevamente

```bash
./autorun.sh
```
