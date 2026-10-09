import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import HTTPException


def request_openai_text(instructions: str, prompt: str, *, max_output_tokens: int = 1200) -> tuple[str, str]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="No AI provider is configured. Use the labeled local demo mode.")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    body = json.dumps(
        {
            "model": model,
            "instructions": instructions,
            "input": prompt,
            "max_output_tokens": max_output_tokens,
        }
    ).encode("utf-8")
    request = Request(
        "https://api.openai.com/v1/responses",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 401:
            raise HTTPException(status_code=502, detail="The AI provider rejected OPENAI_API_KEY. Check the key in the backend environment.") from error
        if error.code == 429:
            raise HTTPException(status_code=502, detail="The AI provider rate limit or account quota was reached. Try again later or check the API account.") from error
        raise HTTPException(status_code=502, detail=f"The AI provider returned HTTP {error.code}. Try again or use the demo mode.") from error
    except URLError as error:
        raise HTTPException(status_code=502, detail="Could not reach the AI provider. Check the backend internet connection or use the demo mode.") from error
    except TimeoutError as error:
        raise HTTPException(status_code=504, detail="The AI analysis timed out. Try again or use the demo mode.") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=502, detail="The AI provider returned an unreadable response. Try again or use the demo mode.") from error
    except OSError as error:
        raise HTTPException(status_code=502, detail="A network error prevented AI analysis. Check the connection or use the demo mode.") from error

    output_parts = []
    for item in payload.get("output", []):
        if item.get("type") == "message":
            output_parts.extend(
                content.get("text", "")
                for content in item.get("content", [])
                if content.get("type") == "output_text"
            )
    result = "\n".join(part for part in output_parts if part.strip()).strip()
    if not result:
        raise HTTPException(status_code=502, detail="The AI provider returned no analysis text. Try again or use the demo mode.")
    return result, model
