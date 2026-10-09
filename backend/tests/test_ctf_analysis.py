import json
import os
import unittest
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi import HTTPException
from pydantic import ValidationError

from backend.app import main


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class CtfAnalysisTests(unittest.TestCase):
    def request(self) -> main.CtfAnalyzeRequest:
        return main.CtfAnalyzeRequest(
            challenge_description="A local ELF reverse-engineering challenge.",
            category="reverse",
            command_input="file challenge.elf; strings challenge.elf",
        )

    def test_local_fallback_analyzes_submitted_text_and_labels_it(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            result = main.ctf_analyze(self.request())

        self.assertEqual(result.mode, "demo")
        self.assertIn("LOCAL DEMO MODE", result.label)
        self.assertIn("`elf`", result.result)
        self.assertIn("does not execute commands", result.result)

    def test_local_fallback_surfaces_signals_outside_selected_category(self) -> None:
        request = main.CtfAnalyzeRequest(
            challenge_description="",
            category="misc",
            command_input="file mystery.elf; strings mystery.elf",
        )
        self.assertIn("`strings` (reverse engineering)", main.analyze_locally(request))

    def test_demo_returns_sample_input_and_explicit_demo_data(self) -> None:
        result = main.ctf_demo()

        self.assertEqual(result.category, "reverse")
        self.assertIn("mystery", result.command_input)
        self.assertIn("DEMO DATA", result.analysis.label)
        self.assertIn("no binary was executed", result.analysis.result)

    def test_openai_response_uses_server_side_key_and_returns_model_analysis(self) -> None:
        fake_response = FakeResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "Inspect the comparison near the prompt."}],
                    }
                ]
            }
        )
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "unit-test-secret", "OPENAI_MODEL": "test-model"}),
            patch.object(main, "urlopen", return_value=fake_response) as mock_urlopen,
        ):
            result = main.ctf_analyze(self.request())

        self.assertEqual(result.mode, "ai")
        self.assertEqual(result.model, "test-model")
        self.assertIn("Inspect the comparison", result.result)
        self.assertNotIn("unit-test-secret", result.result)
        self.assertTrue(mock_urlopen.called)

    def test_openai_auth_error_is_clear_and_does_not_silently_fall_back(self) -> None:
        auth_error = HTTPError("https://api.openai.com/v1/responses", 401, "Unauthorized", {}, BytesIO())
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "invalid-test-key"}),
            patch.object(main, "urlopen", side_effect=auth_error),
        ):
            with self.assertRaises(HTTPException) as raised:
                main.ctf_analyze(self.request())

        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("rejected OPENAI_API_KEY", raised.exception.detail)

    def test_blank_command_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            main.CtfAnalyzeRequest(category="misc", command_input="  ")


if __name__ == "__main__":
    unittest.main()
