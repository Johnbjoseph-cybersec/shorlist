# Scanner images

The Dockerfiles behind the container adapters in `generator/shorlist/adapters/`. Base images
are pinned by digest; each scanner is installed from its project's own source at a fixed
version. Build with network, scan without it:

```sh
docker build -t shorlist-cryptoscan:1.5.0 containers/cryptoscan
docker build -t shorlist-theia:1.1.2      containers/theia
docker build -t shorlist-cipheriq:1.9.3   containers/cipheriq
docker build -t shorlist-qscan:1.0.0      containers/qscan
docker build -t shorlist-semgrep:1.183.0  containers/semgrep
```

cdxgen uses its official image, `ghcr.io/cdxgen/cdxgen:13.6.0`
(`sha256:d3465b2f6e76406a1a4c884deeaf0e869514c4e35c47e415e055bb44596b73ea`). The results in
`results/` were produced with the image IDs recorded in each result's `scanner.command`.
