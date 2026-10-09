# CyberFlow AI

CyberFlow AI is a local, voice-friendly cybersecurity workspace. It brings CTF notes, responsible bug bounty reports, and SOC alert triage into one dark dashboard. User input and saved work remain on the local machine unless an AI provider is configured.

## Problem and solution

Security work is spread across terminals, notes, and report templates. CyberFlow organizes those workflows and turns submitted text into structured guidance. It labels rule-based results as local demo analysis, keeps observations separate from hypotheses, and does not execute commands, query production systems, or perform containment.

## Features

- **Dashboard:** FastAPI and SQLite status, live database metrics, recent saved work, and a quick command router.
- **CTF Analyst:** title, description, category, difficulty, artifacts, question, and command/output input; analyze, sample challenge, save, and Markdown export.
- **Bug Bounty:** finding form, triage, structured disclosure draft, sample data, save, Markdown/JSON export, and an authorization reminder.
- **SOC Analyst:** alert context and multiline log input; analysis, sample alert, indicator extraction, timeline generation, save, and report export.
- **Investigation History:** database-backed search, agent/date filters, sorting, details, export, and confirmed deletion.
- **Reports:** saved report search, type filter, details, Markdown/JSON export, and deletion.
- **Settings:** API/provider and database status, AI/demo mode, model/version, Wispr Flow guidance, and confirmed local data clearing.
- **Wispr Flow compatibility:** standard editable fields accept typing, paste, and desktop dictation text. There is no official Wispr Flow API integration.

## Architecture

- Frontend: React, TypeScript, Vite, and Tailwind CSS.
- Backend: Python FastAPI with Pydantic validation.
- Persistence: SQLite at `backend/data/cyberflow.db`, created when the backend starts. Each saved investigation also creates a linked report.
- AI: optional server-side OpenAI Responses API call. Without `OPENAI_API_KEY`, the analyzers use clearly labeled local, rule-based guidance. Demo sample buttons always return labeled sample data and do not need a key.
- Development proxy: Vite forwards `/api` requests to `127.0.0.1:8000`.

## Requirements

- macOS with Python 3.10 or newer
- Node.js 20 or newer (npm is included)

## Install on Mac

Open Terminal and move into the project folder:

```bash
cd "/Users/gauravgavali/Documents/ChatGPT/CyberFlow Ai"
```

Install the frontend packages:

```bash
npm install
```

Create a Python environment and install the backend packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
```

## Start CyberFlow AI

Keep two Terminal windows open.

**Terminal 1 — backend:** from the project folder, activate the environment and start FastAPI:

```bash
cd "/Users/gauravgavali/Documents/ChatGPT/CyberFlow Ai"
source .venv/bin/activate
cd backend
python -m app
```

The backend runs at `http://127.0.0.1:8000`; interactive API docs are at `http://127.0.0.1:8000/docs`.

**Terminal 2 — frontend:**

```bash
cd "/Users/gauravgavali/Documents/ChatGPT/CyberFlow Ai"
npm run dev
```

Open the Vite address printed in Terminal, usually `http://localhost:5173`.

## Optional AI configuration

Without a key, the app uses its local demo analyzers. To enable model-backed CTF, bug bounty, SOC, and command-router analysis, copy the example configuration:

```bash
cd "/Users/gauravgavali/Documents/ChatGPT/CyberFlow Ai"
cp .env.example .env
```

Edit `.env` and set `OPENAI_API_KEY` to an API key you control. `OPENAI_MODEL` defaults to `gpt-4.1-mini`; set it to a model available to your API account if needed. Restart the backend after changing `.env`. The key is only read by FastAPI and is never returned to the frontend. Submitted text is sent to OpenAI when a key is configured, so do not submit secrets, personal data, or information you are not permitted to share. Provider errors are shown; the app will not silently claim an AI result when a request fails.

## Using Wispr Flow on Mac

Wispr Flow is an external desktop dictation tool. It inserts text into whichever regular input or textarea has focus; CyberFlow does not use a Wispr Flow API or request microphone access.

1. Click the command box or another text field.
2. Start Wispr Flow using the shortcut configured in Wispr Flow settings.
3. Dictate your command, notes, or logs.
4. Read and correct the inserted text.
5. Click the visible Analyze or Route button.

Typing and paste work the same way if Wispr Flow is unavailable. The app does not intercept dictation keystrokes.

## Test the app manually

1. Open **Dashboard** and confirm the live API/database status and zero-valued empty metrics (until you save an investigation).
2. Open **CTF Analyst**, type into the command area, choose **Analyze Challenge**, then try **Try Demo**. Save a result and export it.
3. In **Bug Bounty**, choose **Load Demo**, review its unverified sample draft, then try **Analyze Finding**, **Generate Report**, **Save Investigation**, and Markdown/JSON export.
4. In **SOC Analyst**, choose **Load Demo Alerts**. Check analysis, indicator extraction, and timeline; save the result and export the report.
5. Use the dashboard **Quick investigation** field to type or dictate a request and test automatic or manual routing.
6. Open **Investigation History** and **Reports** to search, filter, open, and export saved items. Try deletion only for records you intend to remove; each delete has a confirmation prompt.
7. Open **Settings** to check AI/demo status and Wispr Flow instructions. Clearing local data permanently removes saved investigations and reports and asks for confirmation.

## Automated checks

From the project folder:

```bash
npm run build
source .venv/bin/activate
python -m unittest discover -s backend/tests -v
```

The backend tests use a temporary SQLite database and mocked AI-provider replies; they do not make paid external API calls.

## Demo walkthrough

1. Dictate or type “Analyze this CTF challenge” in the dashboard router.
2. Load the CTF sample and explain how the analysis separates visible clues from hypotheses.
3. Load the Bug Bounty sample and show the disclosure draft’s explicit “unverified” language.
4. Load the SOC alert sample and show its parsed indicators, timeline, and human-approved-only containment guidance.
5. Save investigations and open History and Reports to show persisted work.
6. Open a report and export Markdown or JSON.

## Limitations and security notes

- Local fallback analysis is deterministic rule-based guidance, not an AI model or a security verification.
- SOC risk scoring is a heuristic, not a probability. IOC values are extracted from text only and are not reputation-checked.
- Generated command suggestions are examples only; the backend never runs them or accesses supplied files.
- CTF, bug bounty, and SOC demo inputs are sample data and should not be presented as real findings.
- SQLite is local, without user accounts, encryption-at-rest, cloud sync, or role-based access control. Protect the computer and database file accordingly.
- API keys belong in the backend `.env`, not frontend environment variables. Do not commit `.env`.
- Wispr Flow use is ordinary desktop text insertion; microphone permissions and dictation are managed by Wispr Flow itself.

## Project layout

```text
backend/
  app/main.py             FastAPI endpoints and CTF analysis
  app/workflows.py        Bug bounty, SOC, and command-router workflows
  app/main_model.py       Server-side OpenAI request helper
  app/database.py         SQLite schema and CRUD operations
  tests/                  Backend and SQLite workflow tests
  data/                   Local database, created on first run
src/
  App.tsx                 Dashboard, navigation, CTF workspace, settings
  Workspaces.tsx          Bug bounty, SOC, history, reports, command router
  styles.css              Dark dashboard and responsive workflow styling
  main.tsx                React entry point
```
