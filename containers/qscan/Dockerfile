# qscan, github.com/EthanCratchley/qscan at commit 8b737992 (NOT the PyPI name "qscan", which is an unrelated astronomy package)
FROM python@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
RUN apt-get update -qq && apt-get install -y -qq git >/dev/null && rm -rf /var/lib/apt/lists/*  && pip install --no-cache-dir "git+https://github.com/EthanCratchley/qscan@8b737992ef65cb8e97e343b2d2bbd1a5eee7d4ef"
USER 65534:65534
ENV HOME=/tmp
ENTRYPOINT ["qscan"]
