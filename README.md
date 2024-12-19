# Zendesk-Exporter

## Docker Install

~~~ shell
docker run --rm -v zendesk.yml:/app/config/zendesk.yml -p 9146:9146 zendesk-exporter
~~~

## Prometheus

```yml
scrape_configs:
  - job_name: 'zendesk'
    metrics_path: /zendesk
    static_configs:
    - targets: ['<ip>:<port>']
```