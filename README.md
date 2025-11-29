# Email Spam Score Checker

A full-stack web application that scores emails for spam risk using multiple heuristics. The project includes a React + TypeScript + Vite frontend, a FastAPI backend, Docker support, and unit tests for the analysis engine.

## Features
- Analyze raw email content or headers.
- SpamAssassin-style heuristics for keywords, punctuation, suspicious URLs, and HTML quality.
- Header checks for SPF, DKIM, and DMARC issues.
- Domain reputation checks for disposable senders, new registrations, and DNSBL hits.
- Extracted links with clickable output.
- Color-coded score categories (SAFE, SUSPICIOUS, LIKELY SPAM).
- Dark/light mode toggle.
- Example spam and legitimate emails for quick testing.
- Local history persisted to `localStorage`.

## Project Structure
```
backend/    # FastAPI service
frontend/   # React + Vite + Tailwind app
```

## Backend Setup (local)
1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Run the API:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
4. Visit `http://localhost:8000/docs` for interactive API docs.

### Backend Tests
Run unit tests for the analysis logic:
```bash
pytest backend/tests
```

## Frontend Setup (local)
1. Install dependencies:
   ```bash
   cd frontend
   npm install
   ```
2. Start the dev server:
   ```bash
   npm run dev
   ```
3. Set the backend URL with `VITE_API_URL` if it differs from `http://localhost:8000`.

## Docker Workflow
Build and run both services with Docker Compose:
```bash
docker-compose up --build
```
- Frontend served at `http://localhost:5173` (proxying to backend URL in `VITE_API_URL`).
- Backend served at `http://localhost:8000`.

### Dockerfiles
- `backend/Dockerfile` builds the FastAPI image and starts `uvicorn`.
- `frontend/Dockerfile` builds the Vite bundle and serves it via `serve` on port `4173`.

## Deploying to Google Cloud Run
Each service can be deployed as its own container:
1. Build images:
   ```bash
   gcloud builds submit --tag gcr.io/PROJECT_ID/spam-backend ./backend
   gcloud builds submit --tag gcr.io/PROJECT_ID/spam-frontend ./frontend
   ```
2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy spam-backend --image gcr.io/PROJECT_ID/spam-backend --platform managed --allow-unauthenticated --port 8000
   gcloud run deploy spam-frontend --image gcr.io/PROJECT_ID/spam-frontend --platform managed --allow-unauthenticated --port 4173 \
     --set-env-vars VITE_API_URL=https://<BACKEND_SERVICE_URL>
   ```
3. Update the frontend environment variable to point to the backend Cloud Run URL.

## Example Input
```
From: winner@mailinator.com
Subject: WIN BIG NOW!!!

Claim now for free money!!! Visit http://bit.ly/spammy
```

## Sample Output
```json
{
  "score": 72,
  "category": "LIKELY_SPAM",
  "rules_triggered": [
    { "name": "SPAM_KEYWORDS", "points": 14, "info": "Found suspicious terms: free money" },
    { "name": "EXCESSIVE_PUNCTUATION", "points": 15, "info": "Found 6 exclamation marks" },
    { "name": "NO_DKIM", "points": 15, "info": "Missing DKIM signature" }
  ],
  "links": ["http://bit.ly/spammy"],
  "headers": {"spf": "fail", "dkim": "missing", "dmarc": "pass"}
}
```

## Notes
- The domain age and DNS blocklist checks are simulated for offline determinism.
- Header validation is lightweight; provide well-formed RFC2822 headers for best results.

