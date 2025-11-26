# LLM-Protect Deployment Guide

This guide covers deploying the LLM-Protect system with Layer-0 Security Filter and Input Preparation Module.

## Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- 4GB+ RAM available
- 10GB+ disk space
- (Optional) Python 3.10+ for local development

## Quick Start with Docker Compose

### 1. Clone Repository

```bash
git clone https://github.com/BlackPool25/LLM-Protect.git
cd LLM-Protect
```

### 2. Configure Environment

Create `.env` file:

```bash
# Layer-0 API Key (change in production!)
LAYER0_API_KEY=your-secure-api-key-here

# Grafana admin password
GRAFANA_PASSWORD=admin
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check service health
docker-compose ps
```

### 4. Access Services

- **Input Prep API**: http://localhost:8080/docs
- **Layer-0 API**: http://localhost:8000/docs
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/your-password)

### 5. Test the System

```bash
# Health check
curl http://localhost:8080/health
curl http://localhost:8000/health

# Test scan (clean input)
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secure-api-key-here" \
  -d '{"user_input": "What is Python?", "external_chunks": []}'

# Test input preparation
curl -X POST http://localhost:8080/api/v1/prepare-text \
  -F "user_prompt=Tell me about security" \
  -F "external_data=[]"
```

## Production Deployment

### Kubernetes Deployment

1. **Build and Push Images**:

```bash
# Build images
docker build -f Dockerfile.layer0 -t ghcr.io/blackpool25/llm-protect/layer0:latest .
docker build -f Dockerfile.inputprep -t ghcr.io/blackpool25/llm-protect/inputprep:latest .

# Push to registry
docker push ghcr.io/blackpool25/llm-protect/layer0:latest
docker push ghcr.io/blackpool25/llm-protect/inputprep:latest
```

2. **Create Kubernetes Manifests**:

See `k8s/` directory for complete manifests.

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/layer0-deployment.yaml
kubectl apply -f k8s/inputprep-deployment.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/ingress.yaml
```

3. **Configure Secrets**:

```bash
kubectl create secret generic layer0-secrets \
  --from-literal=api-key=your-secure-api-key \
  -n llm-protect
```

### Horizontal Scaling

**Layer-0** (stateless, scales horizontally):

```bash
# Scale to 4 replicas
docker-compose up -d --scale layer0=4

# Kubernetes
kubectl scale deployment layer0 --replicas=4 -n llm-protect
```

**Input Prep** (scales with consideration for file uploads):

```bash
# Scale to 3 replicas with shared volume
kubectl scale deployment inputprep --replicas=3 -n llm-protect
```

### Load Balancing

Use **Nginx** or cloud load balancer:

```nginx
upstream layer0_backend {
    least_conn;
    server layer0-1:8000;
    server layer0-2:8000;
    server layer0-3:8000;
    server layer0-4:8000;
}

server {
    listen 80;
    location /layer0/ {
        proxy_pass http://layer0_backend/;
    }
}
```

## Monitoring Setup

### Prometheus Configuration

Metrics are automatically collected from:
- Layer-0: `/metrics` endpoint
- Input Prep: `/metrics` endpoint (if enabled)

Key metrics:
- `layer0_requests_total` - Total scan requests
- `layer0_scan_duration_ms` - Scan latency
- `layer0_rules_matched_total` - Rule matches by severity
- `layer0_circuit_breaker_trips_total` - Circuit breaker events

### Grafana Dashboards

1. Access Grafana at http://localhost:3000
2. Add Prometheus data source: http://prometheus:9090
3. Import dashboards from `monitoring/grafana/dashboards/`

**Key Dashboards**:
- **Layer-0 Overview**: Request rate, latency, rule matches
- **Security Threats**: Blocked requests, top rules triggered
- **Performance**: Prefilter efficiency, scan times
- **System Health**: Resource usage, error rates

### Alerting Rules

Configure in `monitoring/prometheus/alerts.yml`:

```yaml
groups:
  - name: layer0_alerts
    rules:
      - alert: HighRejectionRate
        expr: rate(layer0_requests_total{status="rejected"}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High rejection rate detected"
      
      - alert: SlowScanning
        expr: histogram_quantile(0.99, layer0_scan_duration_ms) > 1000
        for: 5m
        annotations:
          summary: "99th percentile scan time > 1s"
```

## Performance Tuning

### Layer-0 Optimization

1. **Enable Prefilter** (default: enabled):
```yaml
# config
PREFILTER_ENABLED=true
```

2. **Adjust Worker Count**:
```bash
# In Dockerfile.layer0
CMD ["uvicorn", "layer0.api:app", "--workers", "8"]  # CPU cores
```

3. **Tune Rate Limits**:
```python
# layer0/api.py
@limiter.limit("200/minute")  # Increase from 100
```

### Input Prep Optimization

1. **Disable Unused Features**:
```bash
# Disable heavy image processing if not needed
ADVANCED_IMAGE_PROCESSING=false
```

2. **Configure Worker Threads**:
```bash
uvicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
```

## Security Hardening

### 1. Change Default Credentials

```bash
# Generate strong API key
openssl rand -hex 32

# Update .env
LAYER0_API_KEY=<generated-key>
```

### 2. Enable HTTPS

```yaml
# docker-compose.yml - add nginx reverse proxy
nginx:
  image: nginx:alpine
  ports:
    - "443:443"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf
    - ./certs:/etc/nginx/certs
```

### 3. Network Isolation

```yaml
# docker-compose.yml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
```

### 4. Resource Limits

```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

## Troubleshooting

### Layer-0 Not Starting

```bash
# Check logs
docker-compose logs layer0

# Verify datasets loaded
docker exec llm-protect-layer0 ls -la /app/layer0/datasets

# Test API directly
curl http://localhost:8000/health/ready
```

### High Latency

1. Check prefilter is enabled
2. Review rule count: `curl http://localhost:8000/stats`
3. Check Prometheus metrics for bottlenecks
4. Consider scaling horizontally

### False Positives

1. Review matched rules in logs
2. Adjust rule severity in datasets
3. Use ensemble scoring for more nuanced decisions
4. Whitelist specific patterns if needed

### Memory Issues

```bash
# Monitor container memory
docker stats

# Increase limits
docker-compose up -d --scale layer0=2 --memory 4g
```

## Backup and Recovery

### Backup Datasets

```bash
# Backup rule datasets
docker cp llm-protect-layer0:/app/layer0/datasets ./backups/datasets-$(date +%Y%m%d)

# Backup outputs
docker cp llm-protect-inputprep:/app/Outputs ./backups/outputs-$(date +%Y%m%d)
```

### Restore

```bash
# Restore datasets
docker cp ./backups/datasets-20250101 llm-protect-layer0:/app/layer0/datasets

# Reload datasets
curl -X POST http://localhost:8000/datasets/reload \
  -H "X-API-Key: your-api-key"
```

## Updating

### Rolling Update

```bash
# Pull latest images
docker-compose pull

# Recreate services with zero downtime
docker-compose up -d --no-deps --build layer0
docker-compose up -d --no-deps --build inputprep
```

### Kubernetes Rolling Update

```bash
kubectl set image deployment/layer0 \
  layer0=ghcr.io/blackpool25/llm-protect/layer0:v2.0.0 \
  -n llm-protect

# Watch rollout
kubectl rollout status deployment/layer0 -n llm-protect
```

## Support

- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/BlackPool25/LLM-Protect/issues
- **Discussions**: https://github.com/BlackPool25/LLM-Protect/discussions

## License

See LICENSE file for details.
