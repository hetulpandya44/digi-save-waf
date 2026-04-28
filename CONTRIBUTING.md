# Contributing

Thanks for your interest in Digi Save WAF.

## Local Development

```bash
git clone https://github.com/your-username/digi-save-waf.git
cd digi-save-waf
pip install -r requirements.txt
cd backend
python main.py
```

## Running Tests

```bash
cd backend
python tests/test_detection.py
```

## Project Areas

- `backend/` for management APIs and WAF proxy logic
- `backend/detection/` for attack detectors
- `backend/routers/` for API routes
- `frontend/` for the admin UI
- `demo_target/` for the safe local vulnerable sample app

## Contribution Ideas

- improve detection coverage
- add integration tests
- improve dashboard usability
- add production deployment helpers
- strengthen documentation and diagrams

## Security

If you identify a genuine vulnerability in the defensive code, please avoid posting exploitation details publicly before maintainers have time to review.

