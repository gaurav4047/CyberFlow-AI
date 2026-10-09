import ipaddress
import json
import os
import re
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from .main_model import request_openai_text

BugBountyCategory = Literal[
    "xss", "idor", "sqli", "ssrf", "csrf", "authentication", "authorization",
    "information_disclosure", "api_security", "business_logic", "other",
]
SocAction = Literal["analyze", "extract_indicators", "generate_timeline"]
RouterAgent = Literal["auto", "ctf", "bug_bounty", "soc", "general_security"]


class BugBountyRequest(BaseModel):
    action: Literal["analyze", "generate_report"] = "generate_report"
    vulnerability_title: str = Field(min_length=3, max_length=160)
    category: BugBountyCategory
    affected_asset: str = Field(min_length=2, max_length=300)
    endpoint: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=10, max_length=5000)
    steps_to_reproduce: str = Field(min_length=5, max_length=5000)
    expected_behavior: str = Field(min_length=3, max_length=2000)
    actual_behavior: str = Field(min_length=3, max_length=2000)
    impact: str = Field(min_length=5, max_length=3000)
    evidence: str = Field(min_length=1, max_length=5000)
    additional_notes: str = Field(default="", max_length=3000)

    @field_validator(
        "vulnerability_title", "affected_asset", "endpoint", "description",
        "steps_to_reproduce", "expected_behavior", "actual_behavior", "impact", "evidence",
    )
    @classmethod
    def required_fields_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        return cleaned


class SocAnalyzeRequest(BaseModel):
    action: SocAction = "analyze"
    alert_title: str = Field(min_length=3, max_length=160)
    alert_source: str = Field(min_length=2, max_length=160)
    reported_severity: Literal["informational", "low", "medium", "high", "critical", "unknown"] = "unknown"
    timestamp: str = Field(default="", max_length=80)
    raw_logs: str = Field(min_length=1, max_length=12000)
    source_ip: str = Field(default="", max_length=80)
    destination_ip: str = Field(default="", max_length=80)
    username: str = Field(default="", max_length=160)
    domain_hostname: str = Field(default="", max_length=253)
    indicators: str = Field(default="", max_length=3000)
    additional_context: str = Field(default="", max_length=3000)

    @field_validator("alert_title", "alert_source", "raw_logs")
    @classmethod
    def required_soc_fields_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        return cleaned


class RouterRequest(BaseModel):
    command: str = Field(min_length=3, max_length=6000)
    agent: RouterAgent = "auto"

    @field_validator("command")
    @classmethod
    def router_command_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Enter a security command or question.")
        return cleaned


class BugBountyNotesRequest(BaseModel):
    notes: str = Field(min_length=3, max_length=6000)

    @field_validator("notes")
    @classmethod
    def notes_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Enter a finding note to analyze.")
        return cleaned


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    agent: Literal["ctf", "bug_bounty", "soc"]
    input: dict = Field(default_factory=dict)
    result: dict = Field(default_factory=dict)
    severity: str | None = Field(default=None, max_length=40)
    summary: str | None = Field(default=None, max_length=240)


def _openai_enabled() -> bool:
    return bool(os.getenv("OPENAI_API_KEY", "").strip())


def analyze_bug_bounty(request: BugBountyRequest, *, allow_ai: bool = True) -> dict:
    category_label = {
        "xss": "Cross-Site Scripting (CWE-79)",
        "idor": "IDOR / Broken Object-Level Authorization (CWE-639)",
        "sqli": "SQL Injection (CWE-89)",
        "ssrf": "Server-Side Request Forgery (CWE-918)",
        "csrf": "Cross-Site Request Forgery (CWE-352)",
        "authentication": "Authentication Issues",
        "authorization": "Authorization Issues",
        "information_disclosure": "Information Disclosure",
        "api_security": "API Security",
        "business_logic": "Business Logic",
        "other": "Other / needs classification",
    }[request.category]
    evidence = request.evidence.strip()
    is_ai = allow_ai and _openai_enabled()
    ai_analysis = ""
    severity = "AI estimate — review required" if is_ai else "Unrated — human review required"
    cvss = (
        "The supplied fields do not establish attack vector, complexity, privileges, interaction, scope, or confirmed confidentiality/integrity/availability impact. Do not assign a numeric score until those assumptions are verified."
    )
    if is_ai:
        prompt = (
            f"Requested action: {request.action}\nVulnerability title: {request.vulnerability_title}\n"
            f"Category: {category_label}\nAuthorized asset: {request.affected_asset}\nEndpoint: {request.endpoint}\n"
            f"User description: {request.description}\nSteps supplied by user:\n{request.steps_to_reproduce}\n"
            f"Expected: {request.expected_behavior}\nActual: {request.actual_behavior}\n"
            f"User-stated impact: {request.impact}\nEvidence supplied by user:\n{evidence}\n"
            f"Additional notes: {request.additional_notes or '(none)'}"
        )
        instructions = (
            "Create a careful responsible-disclosure draft using only the user's supplied facts. "
            "Keep evidence quoted/attributed as user-provided. Never invent requests, responses, "
            "reproduction results, affected users, or verified impact. Mark unknown facts as unknown. "
            "Severity and CVSS are provisional estimates only; list explicit assumptions and say when "
            "there is insufficient evidence for a score. Do not suggest accessing data beyond the "
            "authorized asset or causing disruption. Use headings: Professional title; Classification; "
            "Severity estimate; CVSS suggestion and assumptions; Executive summary; Description; "
            "Preconditions; Reproduction steps; Expected behavior; Actual behavior; Technical impact; "
            "Business impact; Evidence summary (user-provided); Root-cause hypothesis; Remediation; "
            "Open questions."
        )
        analysis, model = request_openai_text(instructions, prompt, max_output_tokens=1600)
        ai_analysis = analysis
        report_markdown = f"# {request.vulnerability_title}\n\n{analysis}"
        label = f"AI DRAFT · {model} · REVIEW BEFORE SUBMISSION"
        mode = "ai"
        result_text = analysis
    else:
        title = request.vulnerability_title.strip()
        report_markdown = f"""# {title}

> LOCAL DEMO DRAFT — generated from submitted fields only. Not a verified finding.

## 1. Professional vulnerability title
{title}

## 2. Vulnerability classification
{category_label}

## 3. Severity estimate
{severity}

## 4. CVSS suggestion with assumptions
{cvss}

## 5. Executive summary
The reporter describes a potential {category_label} issue on `{request.affected_asset}` at `{request.endpoint}`. This draft records the supplied claim; it does not verify exploitability.

## 6. Description
{request.description}

## 7. Preconditions
Not specified in the submitted evidence. Confirm the required account, role, and state before submission.

## 8. Steps to reproduce
{request.steps_to_reproduce}

## 9. Expected behavior
{request.expected_behavior}

## 10. Actual behavior
{request.actual_behavior}

## 11. Technical impact
{request.impact}

## 12. Business impact
Not independently established. Describe affected users, data, or business process only when supported by authorized evidence.

## 13. Evidence summary — user-provided
{evidence}

## 14. Root-cause hypothesis — unverified
The selected category suggests an access-control or input-handling area to review. The underlying cause is not proven by the supplied fields.

## 15. Remediation
Review the relevant server-side validation and authorization checks; add a regression test for the supplied reproduction case. Confirm a specific fix with the application owner.

## 16. Additional notes
{request.additional_notes or 'None supplied.'}
"""
        label = "LOCAL DEMO DRAFT · NOT AI · NOT A VERIFIED FINDING"
        mode = "demo"
        result_text = report_markdown
        model = None
    if request.action == "analyze":
        assessment = (
            f"Model assessment ({model}):\n{ai_analysis}\n\n"
            if is_ai
            else ""
        )
        result_text = (
            f"FINDING TRIAGE — {label}\n\n"
            f"{assessment}"
            f"Candidate classification: {category_label}.\n"
            f"Reporter-stated observation: {request.actual_behavior}\n\n"
            f"Evidence supplied: {evidence}\n\n"
            "Assessment: this is an unverified report. The supplied information alone does not establish exploitability or severity. "
            "Confirm reproducibility only within the authorized program scope.\n\n"
            "Questions to resolve: Which account roles and test records were used? Can a clean control request show the expected access denial? "
            "Are the response and impact details redacted and attributable to this authorized test?"
        )
    return {
        "mode": mode,
        "label": label,
        "result": result_text,
        "report_markdown": report_markdown,
        "report_json": request.model_dump(mode="json"),
        "classification": category_label,
        "severity_estimate": severity,
        "cvss_suggestion": cvss,
        "evidence_source": "user-provided; not independently verified",
        "model": model,
    }


def analyze_soc(request: SocAnalyzeRequest, *, allow_ai: bool = True) -> dict:
    text = "\n".join(
        [request.raw_logs, request.indicators, request.additional_context, request.source_ip, request.destination_ip]
    )
    action = request.action
    indicators = extract_indicators(text)
    timeline = generate_timeline(request.raw_logs)
    if action == "extract_indicators":
        return {
            "mode": "demo",
            "label": "LOCAL INDICATOR EXTRACTION · RULE-BASED",
            "result": format_indicators(indicators),
            "indicators": indicators,
            "timeline": timeline,
        }
    if action == "generate_timeline":
        return {
            "mode": "demo",
            "label": "LOCAL TIMELINE · PARSED FROM SUPPLIED LOGS",
            "result": format_timeline(timeline),
            "indicators": indicators,
            "timeline": timeline,
        }

    if allow_ai and _openai_enabled():
        prompt = (
            f"Alert: {request.alert_title}\nSource: {request.alert_source}\n"
            f"Severity reported by source: {request.reported_severity}\nTimestamp: {request.timestamp or '(not supplied)'}\n"
            f"Source IP: {request.source_ip or '(not supplied)'}\nDestination IP: {request.destination_ip or '(not supplied)'}\n"
            f"Username/account: {request.username or '(not supplied)'}\nDomain/hostname: {request.domain_hostname or '(not supplied)'}\n"
            f"Indicators supplied: {request.indicators or '(none)'}\nAdditional context: {request.additional_context or '(none)'}\n"
            f"Raw logs:\n{request.raw_logs}"
        )
        instructions = (
            "Act as a cautious SOC triage assistant for the pasted log data only. Do not claim a confirmed attack "
            "from insufficient evidence. Separate observed events from hypotheses. Do not access production systems "
            "or execute containment. Include alert summary, analyst-assessed severity and why, a 0-100 triage "
            "priority score explicitly described as a heuristic and not a probability, suspicious indicators with "
            "provenance, timestamp-ordered timeline, possible attack hypothesis, MITRE ATT&CK mappings only where "
            "the evidence supports them (otherwise say none mapped), alternative explanations, recommended "
            "investigation steps, suggested containment actions requiring analyst approval, confidence, and limitations."
        )
        result, model = request_openai_text(instructions, prompt, max_output_tokens=1800)
        label = f"AI TRIAGE · {model} · HUMAN REVIEW REQUIRED"
        mode = "ai"
        risk_score, analyst_severity = score_soc(request, indicators)
    else:
        risk_score, analyst_severity = score_soc(request, indicators)
        result = format_soc_analysis(request, indicators, timeline, analyst_severity, risk_score)
        label = "LOCAL DEMO TRIAGE · RULE-BASED · NOT A CONFIRMED ATTACK"
        mode = "demo"
        model = None
    report_markdown = f"# SOC Alert: {request.alert_title}\n\n> {label}\n\n{result}"
    return {
        "mode": mode,
        "label": label,
        "result": result,
        "report_markdown": report_markdown,
        "report_json": request.model_dump(mode="json"),
        "severity_estimate": analyst_severity,
        "risk_score": risk_score,
        "indicators": indicators,
        "timeline": timeline,
        "model": model,
    }


def extract_indicators(text: str) -> dict[str, list[str]]:
    ips: list[str] = []
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(candidate)
            if candidate not in ips:
                ips.append(candidate)
        except ValueError:
            pass
    domains = list(dict.fromkeys(
        match.lower().rstrip(".")
        for match in re.findall(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b", text)
    ))
    hashes = list(dict.fromkeys(re.findall(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b", text)))
    usernames = list(dict.fromkeys(re.findall(r"(?i)\b(?:user|username|account)[=: ]+([\w.@-]{2,80})", text)))
    username_set = {value.lower() for value in usernames}
    domains = [domain for domain in domains if domain not in username_set]
    return {"ip_addresses": ips, "domains": domains, "hashes": hashes, "usernames": usernames}


def generate_timeline(logs: str) -> list[dict[str, str]]:
    timeline = []
    time_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
    for line_number, line in enumerate(logs.splitlines(), start=1):
        match = time_pattern.search(line)
        if match:
            timeline.append({"timestamp": match.group(0), "event": line.strip(), "line": str(line_number)})
    return sorted(timeline, key=lambda item: item["timestamp"])


def format_indicators(indicators: dict[str, list[str]]) -> str:
    labels = {"ip_addresses": "IP addresses", "domains": "Domains/hostnames", "hashes": "File hashes", "usernames": "Usernames"}
    found = [f"{labels[key]}: " + (", ".join(values) if values else "none detected") for key, values in indicators.items()]
    return "Extracted only from submitted text (not reputation-checked):\n" + "\n".join(found)


def format_timeline(timeline: list[dict[str, str]]) -> str:
    if not timeline:
        return "No supported ISO-style timestamps were found in the supplied logs. Events were not reordered or inferred."
    return "Timeline parsed from supplied log lines (no missing events inferred):\n" + "\n".join(
        f"- {item['timestamp']} — {item['event']}" for item in timeline
    )


def score_soc(request: SocAnalyzeRequest, indicators: dict[str, list[str]]) -> tuple[int, str]:
    logs = request.raw_logs.lower()
    score = {"informational": 5, "low": 15, "medium": 30, "high": 45, "critical": 60, "unknown": 10}[request.reported_severity]
    if len(re.findall(r"failed|denied|invalid password|authentication failure", logs)) >= 5:
        score += 20
    if any(term in logs for term in ("malware", "ransomware", "credential dump", "exfiltration")):
        score += 25
    if len(indicators["ip_addresses"]) > 1:
        score += 5
    score = min(score, 95)
    severity = "High triage priority" if score >= 60 else "Medium triage priority" if score >= 30 else "Low triage priority"
    return score, severity


def format_soc_analysis(
    request: SocAnalyzeRequest,
    indicators: dict[str, list[str]],
    timeline: list[dict[str, str]],
    severity: str,
    score: int,
) -> str:
    logs = request.raw_logs.lower()
    auth_failures = len(re.findall(r"failed|denied|invalid password|authentication failure", logs))
    hypotheses = []
    mitre = []
    if auth_failures >= 5:
        hypotheses.append(f"Repeated authentication failures ({auth_failures} matching log lines) could indicate password guessing; lockouts, mistyped credentials, or a stale client are alternatives.")
        mitre.append("T1110 — Brute Force (candidate mapping; repeated failures are present, intent is not confirmed)")
    if "powershell" in logs:
        mitre.append("T1059.001 — PowerShell (command interpreter string appears in supplied logs; maliciousness is not established)")
        hypotheses.append("PowerShell appears in the supplied text; it may be routine administration or suspicious execution depending on command, host, and user context.")
    if not hypotheses:
        hypotheses.append("The supplied text is insufficient to identify a specific attack hypothesis.")
    if not mitre:
        mitre.append("No ATT&CK technique mapped from the supplied evidence.")
    observed = "\n".join(f"- {line.strip()}" for line in request.raw_logs.splitlines() if line.strip()) or "- No log lines supplied."
    next_steps = [
        "Validate the alert source, timezone, and event identifiers against the original exported logs.",
        "Check whether the source and destination identities are expected for this host and account.",
        "Correlate adjacent events and compare with a known-good baseline before escalating.",
    ]
    containment = "If corroborating evidence warrants containment, follow your incident-response process and obtain analyst approval. No action was executed."
    return (
        f"## Alert summary\n{request.alert_title} from {request.alert_source}; source-reported severity: {request.reported_severity}.\n\n"
        f"## Analyst-assessed severity\n{severity}; this is a triage priority, not a confirmed incident.\n\n"
        f"## Risk score\n{score}/100 heuristic score (not a probability). It starts from the source severity and adds weight for repeated authentication failures, malware-related terms, and multiple IPs in the supplied text.\n\n"
        f"## Observed events\n{observed}\n\n"
        f"## Suspicious indicators\n{format_indicators(indicators)}\n\n"
        f"## Event timeline\n{format_timeline(timeline)}\n\n"
        f"## Possible attack hypothesis\n{' '.join(hypotheses)}\n\n"
        f"## MITRE ATT&CK candidates\n" + "\n".join(f"- {item}" for item in mitre) + "\n\n"
        "## Alternative explanations\nBenign administrative activity, user error, automated health checks, or incomplete log context may explain these events.\n\n"
        "## Recommended investigation steps\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(next_steps, 1)) + "\n\n"
        f"## Suggested containment\n{containment}\n\n"
        "## Confidence and limitations\nLow to moderate, based only on the pasted text. No production system was queried, no indicator reputation was checked, and no containment action was taken."
    )


def route_command(command: str, requested_agent: RouterAgent) -> dict:
    if requested_agent != "auto":
        intent = requested_agent.upper()
        confidence = "manual selection"
    elif _openai_enabled():
        prompt = "Classify the command as exactly one of CTF, BUG_BOUNTY, SOC, GENERAL_SECURITY. Return only that label.\n\n" + command
        label, model = request_openai_text(
            "You classify short cybersecurity workspace commands. Return only one allowed label. Do not answer the command.",
            prompt,
            max_output_tokens=30,
        )
        match = re.search(r"\b(CTF|BUG_BOUNTY|SOC|GENERAL_SECURITY)\b", label.upper())
        if not match:
            raise HTTPException(status_code=502, detail="The AI router returned an invalid intent label. Try a manual agent selection.")
        intent = match.group(1)
        confidence = f"AI router · {model}"
    else:
        intent = classify_command(command)
        confidence = "deterministic demo router"

    intent_to_agent = {"CTF": "ctf", "BUG_BOUNTY": "bug_bounty", "SOC": "soc", "GENERAL_SECURITY": "general_security"}
    agent = intent_to_agent.get(intent, "general_security")
    if agent == "ctf":
        from .main import CtfAnalyzeRequest, ctf_analyze
        analysis = ctf_analyze(CtfAnalyzeRequest(category="misc", command_input=command))
        result = analysis.result
        mode = analysis.mode
        route = "/api/ctf/analyze"
    elif agent == "soc":
        result = analyze_soc(SocAnalyzeRequest(alert_title="Routed security log review", alert_source="Command router", raw_logs=command))
        route = "/api/soc/analyze"
        mode = result["mode"]
        result = result["result"]
    elif agent == "bug_bounty":
        if _openai_enabled():
            result, model = request_openai_text(
                "Triage the user's security finding note cautiously. Use only supplied facts, mark any classification as a hypothesis, do not invent evidence, and remind the user to test only authorized assets.",
                command,
                max_output_tokens=700,
            )
            mode = f"ai · {model}"
        else:
            result = analyze_bug_bounty_notes(command)
            mode = "demo"
        route = "/api/bug-bounty/quick-analyze"
    else:
        if _openai_enabled():
            result, _ = request_openai_text(
                "Answer as a cautious security educator. Use only provided context, distinguish facts from hypotheses, and limit guidance to authorized defensive or lab work.",
                command,
                max_output_tokens=1000,
            )
            mode = "ai"
        else:
            result = (
                "LOCAL DEMO MODE — GENERAL SECURITY\n\n"
                "I received your question but no AI provider is configured. Rephrase it with the authorized context, "
                "the system or artifact involved, and what you have observed. This demo does not verify external facts.\n\n"
                f"Submitted question:\n{command}"
            )
            mode = "demo"
        route = "/api/router/route"
    return {"intent": intent, "agent": agent, "confidence": confidence, "workflow_path": route, "result": result, "mode": mode}


def classify_command(command: str) -> str:
    text = command.lower()
    patterns = {
        "CTF": ("ctf", "challenge", "flag", "pwn", "reverse engineer", "cryptography", "forensics"),
        "BUG_BOUNTY": ("bug bounty", "vulnerability report", "idor", "xss", "sqli", "ssrf", "reproduction steps", "finding"),
        "SOC": ("soc", "alert", "suspicious log", "authentication log", "ioc", "incident", "source ip", "destination ip"),
    }
    scores = {intent: sum(text.count(word) for word in words) for intent, words in patterns.items()}
    highest = max(scores.values())
    if highest == 0:
        return "GENERAL_SECURITY"
    winners = [intent for intent, score in scores.items() if score == highest]
    return winners[0] if len(winners) == 1 else "GENERAL_SECURITY"


def analyze_bug_bounty_notes(notes: str) -> str:
    lower = notes.lower()
    candidate = next((term for term in ("idor", "xss", "sql injection", "ssrf", "csrf", "authentication", "authorization") if term in lower), None)
    classification = candidate.upper() if candidate else "not determined from the note"
    return (
        "LOCAL DEMO MODE — QUICK FINDING TRIAGE\n\n"
        f"Candidate classification: {classification}. This is a keyword match, not a verification.\n\n"
        "Submitted note (user-provided):\n"
        f"{notes}\n\n"
        "Complete the Bug Bounty form with the authorized asset, endpoint, reproduction steps, expected/actual behavior, impact, and evidence before generating a report. No evidence was inferred."
    )
