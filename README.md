## tunn

Tunnels stuff

### What kinda stuff?

Http stuff for now:

```
TOKEN=<super_secret> ./bin/tunn -to http://127.0.0.1:8000
```

Works for https too!

### How could it be?

This was an excuse to play with http2 reverse proxies and fly.io. So it's a wrapper to the first http2 reverse proxy library I found h2rev2, which is pretty neat.

Picture of essentially exactly what we have setup here https://github.com/aojea/h2rev2/blob/main/diagram.png . I have implemented the - in this diagram hypothetical - client side reverse proxy.

### Is it secure?

Definitely maybe - use at your own risk.

### Quick start

```
make build
```

TOKEN=<super_secret> ./bin/tunn -to http://127.0.0.1:8000

Ask Bryan for the super secret password.
