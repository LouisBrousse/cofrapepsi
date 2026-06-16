# COFRAP — PoC Serverless OpenFaaS

Plateforme de gestion des comptes utilisateurs avec génération automatique de mot de passe et double authentification (TOTP).

## Stack

- **Kubernetes** : K3S (bare metal sur Proxmox)
- **Serverless** : OpenFaaS Community (via Helm)
- **Fonctions** : Python 3.12 (template python3-http)
- **Base de données** : PostgreSQL 15
- **Frontend** : Flask (SSR)
- **Registre** : Docker Hub (`louisb32/*`)

---

## Structure

```
cofrapepsi/
├── stack.yml                  # Configuration OpenFaaS
├── functions/
│   ├── generate-password/     # Génère mot de passe 24 chars + QR code
│   ├── generate-2fa/          # Génère secret TOTP + QR code
│   └── authenticate/          # Authentifie login + password + code 2FA
└── frontend/
    ├── app.py                 # Application Flask
    ├── Dockerfile
    ├── requirements.txt
    ├── static/style.css
    └── templates/
```

---

## Connexion aux VM

> Prérequis : Tailscale connecté sur votre machine.

### Control-plane (k3s-master)

```bash
ssh louis@100.93.122.114
```

### Worker (k8s-w1)

```bash
ssh user@100.93.122.114  # via le master
# ou depuis le réseau local :
ssh user@192.168.1.20
```

### Éviter de retaper le mot de passe (clé SSH)

```bash
ssh-copy-id louis@100.93.122.114
```

### Proxmox (console web)

Accessible via Tailscale : `https://100.118.81.73:8006`

---

## Workflow de mise à jour

### 1. Modifier le code en local

```bash
# Modifier les fichiers dans functions/ ou frontend/
# Puis pousser sur GitHub
git add .
git commit -m "feat: description du changement"
git push origin main
```

### 2. Mettre à jour sur le serveur

Se connecter au control-plane (`k3s-master`) et aller dans le repo :

```bash
cd ~/cofrapepsi && git pull
```

### 3a. Redéployer les fonctions OpenFaaS

```bash
faas-cli build -f stack.yml
faas-cli push -f stack.yml
faas-cli deploy -f stack.yml
```

### 3b. Redéployer le frontend

```bash
docker build -t louisb32/cofrap-frontend:latest ./frontend/
docker push louisb32/cofrap-frontend:latest
kubectl rollout restart deployment/frontend -n frontend
```

> **Note** : si les modifications ne s'affichent pas, Kubernetes utilise l'image en cache. Forcer le pull avec :
> ```bash
> kubectl patch deployment frontend -n frontend \
>   -p '{"spec":{"template":{"spec":{"containers":[{"name":"frontend","imagePullPolicy":"Always"}]}}}}'
> kubectl rollout restart deployment/frontend -n frontend
> ```

### 4. Vérifier

```bash
# État des fonctions
faas-cli list --gateway http://openfaas.local

# État des pods
kubectl get pods -n frontend
kubectl get pods -n openfaas
```

---

## Accès

| Service | URL |
|---|---|
| Frontend | http://cofrap.local |
| Gateway OpenFaaS | http://openfaas.local |

> Requiert `cofrap.local` et `openfaas.local` dans `/etc/hosts` → `100.93.122.114`
