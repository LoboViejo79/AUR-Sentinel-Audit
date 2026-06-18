# Changelog

## 2026-06-17

- Se agregó análisis profundo de indicadores del payload `deps`, inspirado en A1RM4X/AUR-Malware-2026.06-Check.
- Verificación real SHA256/MD5 de candidatos llamados `deps`.
- Revisión de persistencia systemd, mapas eBPF, C2, historiales, staging y caches yay/paru.
- Revisión ampliada de instalaciones y caches npm/bun.
- Nueva pestaña de análisis profundo.
- La pestaña Log pasó a ser una consola de proceso detallada y en tiempo real.
- Los reportes incluyen hallazgos profundos, comprobaciones parciales y la traza del proceso.
- Se corrigió la generación PDF para la API actual de PySide6.
- Se documentaron fuentes, enlaces y atribución MIT en README.md.

## 1.0.0
- Interfaz gráfica portable.
- Detección de distro y AUR helper.
- Escaneo de paquetes AUR con pacman -Qm.
- Comparación con base comunitaria del incidente AUR.
- Análisis de PKGBUILD.
- Consulta arch-audit.
- Revisión de conexiones, servicios, puertos y persistencia básica.
- Reportes HTML, PDF, TXT y JSON.
- README completo para GitHub.
