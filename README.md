# VulnPriority

This repo contains every information containing my project including the final product

It contains:
- FastAPI AI backend for vulnerability risk scoring
- Frontend dashboard for viewing findings and AI scores
- Shared CI/CD security pipeline for Semgrep, Trivy, ZAP, and DefectDojo imports
- Product-specific CI/CD configs for DVNA, Juice Shop, DVWA, and NodeGoat

The vulnerable applications are kept in separate forked repositories. Each app repo uses a small GitHub Actions wrapper that calls the shared pipeline in this repository.
