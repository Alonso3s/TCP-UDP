# Proyecto Grupo 5 - Capa de Transporte

Sistema en Python para capturar, parsear y analizar tráfico TCP/UDP en una red controlada.

## Estado actual

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Pruebas unitarias iniciales del parser.

## Instalación

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Pruebas

```powershell
pytest
```

## Alcance

Este repositorio sigue la guía de `PROYECTO_Grupo5_Transporte.md`: scapy se puede usar para
capturar o generar tráfico, pero el parser de transporte debe interpretar las cabeceras desde
bytes crudos.
