# Setup Guide

## Requirements

- Python 3.9 or newer
- `pip`
- Windows, Linux, or macOS

Optional:

- Docker and Docker Compose
- DB Browser for SQLite

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/digi-save-waf.git
cd digi-save-waf
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the management server

```bash
cd backend
python main.py
```

This launches:

- management UI on `http://localhost:8005`
- WAF proxy on `http://localhost:8085`

### 4. Start the demo target

In another terminal:

```bash
cd demo_target
python app.py
```

This launches the vulnerable demo app on:

- `http://127.0.0.1:8090`

### 5. Sign in

Default admin credentials:

- username: `admin`
- password: `admin123`

Change them from `Settings -> Security` after first launch.

## Docker Setup

### Build the image

```bash
docker build -t digi-save-waf .
```

### Run the container

```bash
docker run -p 8005:8005 -p 8085:8085 digi-save-waf
```

### Or use compose

```bash
docker compose up --build
```

## Test the Health Endpoint

```bash
curl http://localhost:8005/api/open/health
```

Expected response should contain:

- `status: healthy`

## Safe Demo Notes

- The main application is safe to publish.
- The `demo_target` app is intentionally vulnerable and should stay local or in a private lab environment only.

