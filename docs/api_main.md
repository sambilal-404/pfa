# API Main (`api/app.py` or `api/main.py`)

*(Note: Ensure you are using the correct filename based on your directory structure, either `app.py` or `main.py` in the `src/api` folder)*

## Purpose of the file
This file exposes your Python backend as a RESTful HTTP API using the **FastAPI** framework. It allows Ayoub's Gateway or external systems to send HTTP traffic to your engine and receive a JSON verdict.

## Step-by-Step Explanation
1. **FastAPI Instance:** It creates the `app = FastAPI(...)` object.
2. **Data Models:** It uses Pydantic `BaseModel` to strictly define what an incoming request should look like (`DetectionRequest`) and what the output looks like (`DetectionResponse`).
3. **Endpoints:**
   - `@app.get("/health")`: A simple endpoint to verify the API is running.
   - `@app.post("/detect")`: The main endpoint. It receives the JSON payload, unpacks it, passes it to your `DetectionEngine`, and formats the response.

## Important Functions & Classes
- `BaseModel` (from `pydantic`): This acts as automatic validation. If an external service sends a `/detect` request but forgets the `ip_address` field, FastAPI automatically rejects it with a 422 Error. You don't have to write any `if not ip_address:` checks!
- `Depends()` (if used for engine injection): Allows FastAPI to manage the lifecycle of your `DetectionEngine` so you don't recreate it on every single request.

## Real Examples from My Code
When you hit the API:
```json
{
  "method": "POST",
  "url": "/login",
  "ip_address": "1.1.1.1",
  "body": "SELECT * FROM users",
  "headers": {}
}
```
FastAPI converts this JSON directly into a `DetectionRequest` object. Your route handler then calls `engine.analyze(...)` and returns a `DetectionResponse` which FastAPI automatically serializes back into JSON.

## Key Decisions & Why They Matter
1. **Choosing FastAPI:** FastAPI is natively asynchronous and extremely fast compared to Flask. It also generates automatic Swagger UI documentation (at `/docs`), which makes integration with your teammates (like Ayoub) incredibly easy.
2. **Strict Typing:** Using Pydantic means your API is secure from malformed JSON attacks right at the front door, before the Detection Engine even sees the traffic.
