# xfo-lws

Servidor de billetera ligera de 0xForce — Implementación de la [API REST de billetera ligera Monero](https://github.com/monero-project/meta/blob/master/api/lightwallet_rest.md) (compatible con MyMonero).

Los clientes pueden enviar su clave de vista Monero via la API REST, y el servidor escaneará continuamente las transacciones entrantes en la blockchain.

Diferencias con OpenMonero:
- LMDB en lugar de MySQL
- Claves de vista almacenadas en base de datos — escaneo continuo en segundo plano
- Interfaz ZeroMQ con `monerod` con soporte de suscripción de cadena (push)
- Aceleración ASM amd64 del proyecto Monero, si está disponible
- Soporte de notificaciones webhook, incluyendo notificación "0-conf"

## Inicio Rápido (Docker)

```bash
docker pull ghcr.io/vtnerd/xfo-lws
```

## Compilar desde Código Fuente

```bash
git clone https://github.com/vtnerd/xfo-lws.git
mkdir xfo-lws/build && cd xfo-lws/build
git submodule update --init --recursive
cmake -DCMAKE_BUILD_TYPE=Release ../
make -j$(nproc)
```

Los ejecutables resultantes se encuentran en `xfo-lws/build/src`.

## Ejecución

```bash
./src/xfo-lws-daemon
```

Use `./src/xfo-lws-daemon --help` para listar todas las opciones disponibles.

## Licencia

Ver [LICENSE](LICENSE).

---

Para instrucciones completas de compilación avanzada, etiquetas Docker e información de versiones, consulte el [README.md](README.md) en inglés.
