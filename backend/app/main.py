from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

from . import database
from .main_model import request_openai_text
from .database import (
    clear_local_data,
    create_investigation,
    delete_investigation,
    delete_report,
    get_investigation,
    get_report,
    initialize_database,
    list_investigations,
    list_reports,
    overview,
)
from .workflows import (
    BugBountyRequest,
    BugBountyNotesRequest,
    InvestigationCreate,
    RouterRequest,
    SocAnalyzeRequest,
    analyze_bug_bounty,
    analyze_bug_bounty_notes,
    analyze_soc,
    classify_command,
    route_command,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="CyberFlow AI API",
    description="API for the CyberFlow AI cybersecurity workspace.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


CtfCategory = Literal["web", "pwn", "crypto", "reverse", "forensics", "osint", "misc", "mobile"]
CtfDifficulty = Literal["unknown", "beginner", "intermediate", "advanced"]


class CtfAnalyzeRequest(BaseModel):
    challenge_title: str = Field(default="Untitled challenge", max_length=160)
    challenge_description: str = Field(default="", max_length=4000)
    category: CtfCategory
    difficulty: CtfDifficulty = "unknown"
    challenge_artifacts: str = Field(default="", max_length=6000)
    user_question: str = Field(default="", max_length=2000)
    command_input: str = Field(min_length=1, max_length=6000)

    @field_validator("command_input")
    @classmethod
    def command_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Enter a command, output, or note to analyze.")
        return cleaned


class CtfAnalysisResponse(BaseModel):
    mode: Literal["ai", "demo"]
    label: str
    result: str
    model: str | None = None
    report_markdown: str = ""
    report_json: dict = Field(default_factory=dict)


class CtfDemoResponse(BaseModel):
    challenge_title: str
    challenge_description: str
    category: CtfCategory
    difficulty: CtfDifficulty
    challenge_artifacts: str
    user_question: str
    command_input: str
    analysis: CtfAnalysisResponse


DEMO_CHALLENGE = CtfAnalyzeRequest(
    challenge_title="Mystery Access Phrase",
    challenge_description=(
        "A small Linux ELF executable is provided in an authorized reverse-engineering CTF. "
        "The prompt says the flag is checked locally; no source code is included."
    ),
    category="reverse",
    command_input=(
        "$ file ./mystery\n"
        "mystery: ELF 64-bit LSB pie executable, x86-64, dynamically linked\n"
        "$ strings ./mystery | grep -iE 'flag|ctf|password'\n"
        "Enter access phrase:\n"
        "Access denied"
    ),
)


def analyze_locally(request: CtfAnalyzeRequest) -> str:
    """Provide transparent keyword-based guidance when no model key is configured."""
    combined = f"{request.challenge_description}\n{request.challenge_artifacts}\n{request.command_input}".lower()
    category_names = {
        "web": "web security",
        "pwn": "binary exploitation",
        "crypto": "cryptography",
        "reverse": "reverse engineering",
        "forensics": "digital forensics",
        "osint": "open-source intelligence",
        "misc": "miscellaneous",
        "mobile": "mobile security",
    }
    keyword_groups = {
        "web": ("http", "cookie", "sql", "endpoint", "request", "html", "token"),
        "pwn": ("overflow", "segfault", "gdb", "canary", "buffer", "libc", "rop"),
        "crypto": ("cipher", "xor", "base64", "hex", "nonce", "key", "encrypt"),
        "reverse": ("elf", "binary", "strings", "readelf", "disassembl", "executable", "access phrase"),
        "forensics": ("pcap", "exif", "metadata", "timestamp", "memory dump", "artifact"),
        "osint": ("username", "profile", "domain", "public record", "archive", "geolocation"),
        "misc": ("encoded", "archive", "image", "hint", "puzzle"),
        "mobile": ("apk", "ipa", "android", "ios", "manifest", "certificate pinning"),
    }
    category_matches = [word for word in keyword_groups[request.category] if word in combined]
    if category_matches:
        signal_text = ", ".join(f"`{word}`" for word in category_matches[:6])
    else:
        related_matches = [
            (word, category_names[group])
            for group, words in keyword_groups.items()
            if group != request.category
            for word in words
            if word in combined
        ]
        signal_text = (
            ", ".join(f"`{word}` ({name})" for word, name in related_matches[:6])
            if related_matches
            else "No category-specific keywords were recognized in the submitted text."
        )

    next_steps = {
        "web": "Map the stated routes and parameters, then compare normal and boundary-case responses in the authorized challenge environment.",
        "pwn": "Confirm the provided binary and architecture, reproduce the crash locally, and inspect mitigations before forming an exploit hypothesis.",
        "crypto": "Preserve the original bytes, identify the input and output encodings, and test one transformation at a time against known challenge samples.",
        "reverse": "Start with file metadata and imported symbols, then trace the local input check in a disassembler or debugger. Treat strings as clues, not proof of a flag.",
        "forensics": "Keep an untouched copy of the artifact, record its hash, and inspect metadata and timestamps before drawing conclusions.",
        "osint": "Record each public source and timestamp, corroborate claims across independent sources, and avoid accessing private accounts or restricted data.",
        "misc": "Separate observed facts from guesses, preserve the original artifact, and test the challenge hint against the smallest reproducible case.",
        "mobile": "Inspect the supplied package offline first; record its hash and manifest metadata before testing it in an isolated emulator.",
    }
    question = request.user_question.strip() or "No specific question supplied."
    artifacts = request.challenge_artifacts.strip() or "No separate artifact text supplied."
    return f"""LOCAL RULE-BASED CTF TRIAGE (not an AI model)

## Challenge summary
{request.challenge_title} — {category_names[request.category]}, difficulty {request.difficulty}. {request.challenge_description or 'No challenge description supplied.'}

## Attack surface
The analysis is limited to the description, pasted artifact notes, and command output below. Nothing was executed and no files were inspected.

## Important clues
{signal_text}

## Likely concept (hypothesis only)
The selected category is {category_names[request.category]}. Keyword matching does not confirm a vulnerability, solve, or flag.

## Investigation strategy
{next_steps[request.category]}

## Step-by-step learning guidance
1. Restate the challenge goal and list only the evidence visible in the prompt.
2. Make one hypothesis from the supplied clues and choose a small test in the authorized challenge environment.
3. Record the exact input and output; revise the hypothesis when observations disagree.

## Suggested tools and commands (examples only; not executed)
`file <artifact>` and `sha256sum <artifact>` can identify and fingerprint a local artifact. Choose category-specific tools only after confirming the artifact type.

## Expected observations
Record the exact output, error, or state change for each test. No output is inferred from the supplied notes.

## Supplied artifact notes
{artifacts}

## User question
{question}

## Next steps
{next_steps[request.category]}

## Write-up template
- Challenge and category:
- Goal:
- Observed evidence:
- Hypothesis:
- Reproduction steps:
- Result / flag (only if verified):

## Limitations
This is local rule-based demo guidance, not model output. It does not execute commands, inspect files, contact external systems, or confirm a flag.
"""


def analyze_with_openai(request: CtfAnalyzeRequest, api_key: str) -> tuple[str, str]:
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    prompt = (
        f"Challenge title: {request.challenge_title}\nCategory: {request.category}\nDifficulty: {request.difficulty}\n\n"
        f"Challenge description:\n{request.challenge_description or '(not provided)'}\n\n"
        f"Challenge artifacts / notes:\n{request.challenge_artifacts or '(not provided)'}\n\n"
        f"User question:\n{request.user_question or '(not provided)'}\n\n"
        f"Commands, output, or notes supplied by the user:\n{request.command_input}"
    )
    payload = json.dumps(
        {
            "model": model,
            "instructions": (
                "You are a careful CTF analysis assistant. The user is working on an authorized, "
                "isolated challenge. Analyze only the supplied challenge description and text. "
                "Separate observations from hypotheses, suggest a few safe next steps, and explain "
                "why. Never claim to have run a command, inspected an artifact, or found a flag "
                "unless that evidence appears in the supplied text. Keep advice within the CTF. "
                "Return sections for challenge summary, attack surface, important clues, likely concept "
                "(clearly labeled as a hypothesis), investigation strategy, step-by-step learning guidance, "
                "suggested tools and commands (examples only, never executed), expected observations, next steps, "
                "expected observations, next steps, and a concise write-up template. Do not execute commands or target external systems."
            ),
            "input": prompt,
            "max_output_tokens": 900,
        }
    ).encode("utf-8")
    api_request = Request(
        "https://api.openai.com/v1/responses",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(api_request, timeout=45) as response:
            response_body = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 401:
            raise HTTPException(status_code=502, detail="The AI provider rejected OPENAI_API_KEY. Check the key in the backend environment.") from error
        if error.code == 429:
            raise HTTPException(status_code=502, detail="The AI provider rate limit or account quota was reached. Try again later or check the API account.") from error
        raise HTTPException(status_code=502, detail=f"The AI provider returned HTTP {error.code}. Try again or use Try Demo.") from error
    except URLError as error:
        raise HTTPException(status_code=502, detail="Could not reach the AI provider. Check the backend internet connection or use Try Demo.") from error
    except TimeoutError as error:
        raise HTTPException(status_code=504, detail="The AI analysis timed out. Try again or use Try Demo.") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=502, detail="The AI provider returned an unreadable response. Try again or use Try Demo.") from error

    output_parts = []
    for item in response_body.get("output", []):
        if item.get("type") == "message":
            output_parts.extend(
                content.get("text", "")
                for content in item.get("content", [])
                if content.get("type") == "output_text"
            )
    result = "\n".join(part for part in output_parts if part.strip()).strip()
    if not result:
        raise HTTPException(status_code=502, detail="The AI provider returned no analysis text. Try again or use Try Demo.")
    return result, model


@app.get("/api/health")
def health() -> dict[str, object]:
    started = time.perf_counter()
    database_status = "ok"
    try:
        with database.connect() as connection:
            connection.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        database_status = "error"

    return {
        "status": "ok" if database_status == "ok" else "degraded",
        "service": "CyberFlow AI API",
        "database": database_status,
        "response_time_ms": round((time.perf_counter() - started) * 1000, 2),
    }


@app.post("/api/ctf/analyze", response_model=CtfAnalysisResponse)
def ctf_analyze(request: CtfAnalyzeRequest) -> CtfAnalysisResponse:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        result = analyze_locally(request)
        return CtfAnalysisResponse(
            mode="demo",
            label="LOCAL DEMO MODE · NO AI API KEY CONFIGURED",
            result=result,
            report_markdown=f"# {request.challenge_title}\n\n{result}",
            report_json=request.model_dump(mode="json"),
        )

    result, model = analyze_with_openai(request, api_key)
    return CtfAnalysisResponse(
        mode="ai",
        label=f"AI ANALYSIS · {model}",
        result=result,
        model=model,
        report_markdown=f"# {request.challenge_title}\n\n{result}",
        report_json=request.model_dump(mode="json"),
    )


@app.get("/api/ctf/demo", response_model=CtfDemoResponse)
def ctf_demo() -> CtfDemoResponse:
    analysis = (
        "DEMO DATA — SAMPLE WALKTHROUGH (no binary was executed)\n\n"
        "Initial read\nThe sample is a 64-bit Linux ELF. The visible prompt and rejection text suggest "
        "a local input-validation path, but do not reveal the expected phrase.\n\n"
        "Signals found\n`file` identifies the format and architecture. `strings` exposes the prompt "
        "and rejection message; it does not show a flag in the supplied output.\n\n"
        "Suggested next steps\n1. Record the sample hash and preserve the original file.\n"
        "2. Inspect imports and disassembly around the prompt and comparison.\n"
        "3. Test candidate inputs only against the provided local challenge binary.\n\n"
        "Caveat\nThis is illustrative DEMO DATA. No file was uploaded or inspected, and no flag is claimed."
    )
    return CtfDemoResponse(
        challenge_title=DEMO_CHALLENGE.challenge_title,
        challenge_description=DEMO_CHALLENGE.challenge_description,
        category=DEMO_CHALLENGE.category,
        difficulty=DEMO_CHALLENGE.difficulty,
        challenge_artifacts=DEMO_CHALLENGE.challenge_artifacts,
        user_question=DEMO_CHALLENGE.user_question,
        command_input=DEMO_CHALLENGE.command_input,
        analysis=CtfAnalysisResponse(
            mode="demo",
            label="DEMO DATA · SAMPLE CTF ANALYSIS",
            result=analysis,
        ),
    )


BUG_BOUNTY_DEMO = BugBountyRequest(
    vulnerability_title="Project document accessible across accounts",
    category="idor",
    affected_asset="Authorized local demo application",
    endpoint="GET /api/projects/204/document",
    description="A researcher reports that changing the project identifier may return a document belonging to a different test account.",
    steps_to_reproduce="1. Sign in to the two seeded demo accounts.\n2. Open a document owned by account A.\n3. In the authorized demo environment, change the project identifier to the documented account B sample.",
    expected_behavior="The server should verify the signed-in account can access the requested document.",
    actual_behavior="The reporter states that the response contained a document for the other demo account; this sample has not been independently reproduced.",
    impact="Potential cross-account access to project documents if the report is reproducible.",
    evidence="DEMO DATA: illustrative response note only; no real application or account was accessed.",
    additional_notes="Use only an explicitly authorized program and redact personal data.",
)

SOC_DEMO = SocAnalyzeRequest(
    alert_title="Repeated authentication failures followed by success",
    alert_source="DEMO DATA · sample authentication export",
    reported_severity="medium",
    timestamp="2026-10-09T10:14:00Z",
    raw_logs=(
        "2026-10-09T10:12:01Z auth failed user=demo.admin src=203.0.113.44\n"
        "2026-10-09T10:12:08Z auth failed user=demo.admin src=203.0.113.44\n"
        "2026-10-09T10:12:16Z auth failed user=demo.admin src=203.0.113.44\n"
        "2026-10-09T10:12:29Z auth failed user=demo.admin src=203.0.113.44\n"
        "2026-10-09T10:12:50Z auth failed user=demo.admin src=203.0.113.44\n"
        "2026-10-09T10:13:42Z auth success user=demo.admin src=203.0.113.44 host=portal.example.test"
    ),
    source_ip="203.0.113.44",
    username="demo.admin",
    domain_hostname="portal.example.test",
    additional_context="All values are reserved sample data for the local demo. No real host was queried.",
)


@app.get("/api/overview")
def get_overview() -> dict:
    try:
        return overview()
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Could not read workspace metrics from the local database.") from error


@app.get("/api/settings")
def get_settings() -> dict:
    return {
        "provider": "OpenAI" if os.getenv("OPENAI_API_KEY", "").strip() else "Not configured",
        "ai_configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
        "model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        "mode": "AI enabled" if os.getenv("OPENAI_API_KEY", "").strip() else "Local demo mode",
        "version": app.version,
        "database_path": str(database.DATABASE_PATH),
        "voice_input": "Wispr Flow desktop dictation inserts text into focused browser fields; no official API integration.",
    }


def _server_error(error: sqlite3.Error) -> HTTPException:
    return HTTPException(status_code=503, detail="The local database operation failed. Check that the database file is writable.")


@app.post("/api/bug-bounty/analyze")
def bug_bounty_analyze(request: BugBountyRequest) -> dict:
    return analyze_bug_bounty(request)


@app.post("/api/bug-bounty/quick-analyze")
def bug_bounty_quick_analyze(request: BugBountyNotesRequest) -> dict:
    if os.getenv("OPENAI_API_KEY", "").strip():
        result, model = request_openai_text(
            "Triage the user's security finding note cautiously. Use only supplied facts, mark classifications as hypotheses, do not invent evidence, and remind the user to test only authorized assets.",
            request.notes,
            max_output_tokens=700,
        )
        return {"mode": "ai", "label": f"AI QUICK TRIAGE · {model} · HUMAN REVIEW REQUIRED", "result": result, "model": model}
    return {"mode": "demo", "label": "LOCAL DEMO MODE · QUICK FINDING TRIAGE", "result": analyze_bug_bounty_notes(request.notes)}


@app.get("/api/bug-bounty/demo")
def bug_bounty_demo() -> dict:
    result = analyze_bug_bounty(BUG_BOUNTY_DEMO, allow_ai=False)
    result["label"] = "DEMO DATA · SAMPLE BUG BOUNTY DRAFT"
    result["mode"] = "demo"
    result["input"] = BUG_BOUNTY_DEMO.model_dump(mode="json")
    result["result"] = "DEMO DATA — sample fields loaded for demonstration.\n\n" + result["result"]
    result["report_markdown"] = "> DEMO DATA — sample only; not a verified vulnerability.\n\n" + result["report_markdown"]
    return result


@app.post("/api/soc/analyze")
def soc_analyze(request: SocAnalyzeRequest) -> dict:
    return analyze_soc(request)


@app.get("/api/soc/demo")
def soc_demo() -> dict:
    result = analyze_soc(SOC_DEMO, allow_ai=False)
    result["label"] = "DEMO DATA · SAMPLE SOC TRIAGE"
    result["mode"] = "demo"
    result["result"] = "DEMO DATA — reserved sample indicators only.\n\n" + result["result"]
    result["report_markdown"] = "> DEMO DATA — no real system was investigated.\n\n" + result["report_markdown"]
    result["input"] = SOC_DEMO.model_dump(mode="json")
    return result


@app.post("/api/router/route")
def router_route(request: RouterRequest) -> dict:
    return route_command(request.command, request.agent)


@app.post("/api/investigations")
def save_investigation(request: InvestigationCreate) -> dict:
    try:
        return create_investigation(
            title=request.title,
            agent=request.agent,
            input_data=request.input,
            result_data=request.result,
            severity=request.severity,
            summary=request.summary,
        )
    except sqlite3.Error as error:
        raise _server_error(error) from error


@app.get("/api/investigations")
def investigations_list(
    search: str = "", agent: str = "all", date_from: str = "", date_to: str = "", sort: str = "newest"
) -> list[dict]:
    try:
        return list_investigations(search=search, agent=agent, date_from=date_from, date_to=date_to, sort=sort)
    except sqlite3.Error as error:
        raise _server_error(error) from error


@app.get("/api/investigations/{investigation_id}")
def investigation_detail(investigation_id: str) -> dict:
    try:
        item = get_investigation(investigation_id)
    except sqlite3.Error as error:
        raise _server_error(error) from error
    if item is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return item


@app.delete("/api/investigations/{investigation_id}")
def investigation_remove(investigation_id: str) -> dict:
    try:
        deleted = delete_investigation(investigation_id)
    except sqlite3.Error as error:
        raise _server_error(error) from error
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"deleted": True}


@app.delete("/api/reports/{report_id}")
def report_remove(report_id: str) -> dict:
    try:
        deleted = delete_report(report_id)
    except sqlite3.Error as error:
        raise _server_error(error) from error
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"deleted": True}


@app.get("/api/reports")
def reports_list(search: str = "", agent: str = "all") -> list[dict]:
    try:
        return list_reports(search=search, agent=agent)
    except sqlite3.Error as error:
        raise _server_error(error) from error


@app.get("/api/reports/{report_id}")
def report_detail(report_id: str) -> dict:
    try:
        report = get_report(report_id)
    except sqlite3.Error as error:
        raise _server_error(error) from error
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@app.delete("/api/data")
def data_clear() -> dict:
    try:
        clear_local_data()
    except sqlite3.Error as error:
        raise _server_error(error) from error
    return {"cleared": True}
