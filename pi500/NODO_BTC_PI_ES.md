# NODO BITCOIN SOBERANO — PLAN DE ARQUITECTURA (X-39)

## REGLA DE HIERRO
La Pi 500 es el firmador COLD air-gapped. NUNCA se conecta a ninguna red.
El nodo Bitcoin es una SEGUNDA maquina, siempre online. Roles mutuamente excluyentes.

```
[Pi 500 - COLD]          [Pi 5 - NODO BTC]           [Servidor X-39]
 air-gapped               online 24/7                 Emergent (produccion)
 clave ML-DSA-87          Bitcoin Core (pruned)       OTS stamp via calendarios
 co-firma offline         verifica sellos OTS         guarda proof.ots
 sneakernet (USB)         RPC local                   publica bundles
```

## PROPOSITO DEL NODO
Hoy X-39 verifica los sellos OpenTimestamps contra exploradores/calendarios
publicos (terceros). Con nodo propio la verificacion es soberana:
"no confies, verifica" hasta la ultima capa. Cero dependencia externa.

Dato tecnico clave: verificar un sello OTS solo requiere el HEADER del bloque
(merkle root). Un nodo PODADO (pruned) conserva todos los headers.
=> NO hace falta nodo archival de 800+ GB. Un pruned de ~10 GB es suficiente.

## HARDWARE RECOMENDADO (segunda maquina)
| Pieza | Opcion | Coste aprox |
|---|---|---|
| Placa | Raspberry Pi 5, 8 GB RAM | ~90 EUR |
| Disco | SSD NVMe 512 GB + HAT M.2 (pruned sobra; 2 TB si algun dia quieres archival) | ~60-70 EUR |
| Alimentacion | Fuente oficial 27W | ~15 EUR |
| Caja | Con ventilacion activa | ~15 EUR |
| **Total** | | **~180 EUR** |

Alternativa coste cero: cualquier PC viejo con 4+ GB RAM y un SSD.

## SOFTWARE
- Raspberry Pi OS Lite 64-bit (sin escritorio; solo SSH desde tu LAN).
- Bitcoin Core (compilado o binario oficial, verificando firmas GPG de release).
- NADA de stacks tipo Umbrel para esto: capas innecesarias. Bitcoin Core pelado.

### bitcoin.conf minimo
```
server=1
prune=10000          # ~10 GB de bloques; headers completos siempre
rpcuser=x39node
rpcpassword=<GENERAR ALEATORIA>
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
dbcache=1000
```

### Sincronizacion inicial (IBD)
En una Pi 5 con SSD: 2-4 dias. Se hace una sola vez. Dejarla trabajar.

## INTEGRACION CON X-39 — TRES NIVELES (incrementales)

### Nivel 1 — Auditoria personal (dia 1 tras el IBD)
Verificar cualquier bundle descargado de la app contra TU nodo:
```
ots --bitcoin-node http://x39node:PASS@127.0.0.1:8332/ verify proof.ots
```
Resultado: confirmacion del sello leyendo el header desde tu propia copia
de la cadena. Cero terceros.

### Nivel 2 — Auditor automatico (cron)
Script en el nodo que cada N horas descarga los bundles publicos de la app
(GET /proof/{aid}.zip), verifica cada .ots contra el nodo local y escribe
un log firmado de auditoria. Deteccion inmediata si algun sello no cuadra.

### Nivel 3 — Endpoint de verificacion soberana (futuro, opcional)
Exponer un endpoint minimo de verificacion (solo lectura) desde el nodo via
Tor hidden service o tunel (Tailscale/WireGuard), para que el backend de X-39
pueda mostrar "verificado contra nodo soberano" ademas de los calendarios
publicos. Requiere diseno cuidadoso: el nodo NUNCA expone el RPC crudo a
internet, solo un proxy de verificacion sin estado.

## ORDEN DE EJECUCION
1. (BLOQUEADO) Llega la Pi 500 -> FASE 1: keygen COLD air-gapped (GUIA_CONCURSO_ES.md).
2. Comprar/reciclar segunda maquina para el nodo.
3. Instalar OS + Bitcoin Core, arrancar IBD (2-4 dias).
4. Nivel 1: verificar manualmente un bundle real de produccion.
5. Nivel 2: cron auditor.
6. (Opcional) Nivel 3: endpoint soberano.

## NOTA PARA BDF
Este plan es exactamente la linea "Equipment: air-gapped signing hardware +
dedicated Bitcoin full node for sovereign timestamp verification" del
presupuesto de la solicitud BDF ($1,500). Coherencia total entre lo pedido
y lo planificado.
