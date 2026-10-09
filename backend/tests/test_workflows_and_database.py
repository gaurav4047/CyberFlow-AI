import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from backend.app import database, main
from backend.app.workflows import (
    BugBountyRequest,
    BugBountyNotesRequest,
    RouterRequest,
    SocAnalyzeRequest,
    analyze_bug_bounty,
    analyze_soc,
    classify_command,
    route_command,
)


class WorkflowsAndDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "cyberflow-test.db"
        self.path_patch = patch.object(database, "DATABASE_PATH", self.path)
        self.data_patch = patch.object(database, "DATA_DIR", Path(self.temp_dir.name))
        self.path_patch.start()
        self.data_patch.start()
        database.initialize_database()

    def tearDown(self) -> None:
        self.data_patch.stop()
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_bug_bounty_demo_draft_preserves_evidence_and_limitations(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            result = analyze_bug_bounty(main.BUG_BOUNTY_DEMO)
        self.assertEqual(result["mode"], "demo")
        self.assertIn("not a verified finding", result["result"].lower())
        self.assertIn("DEMO DATA", result["report_markdown"])
        self.assertEqual(result["evidence_source"], "user-provided; not independently verified")

    def test_bug_bounty_validates_required_fields(self) -> None:
        with self.assertRaises(ValidationError):
            BugBountyRequest(category="idor")
        with self.assertRaises(ValidationError):
            BugBountyNotesRequest(notes=" ")

    def test_bug_bounty_ai_triage_contains_actual_model_response(self) -> None:
        from unittest.mock import patch as mock_patch

        with (
            mock_patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}),
            mock_patch("backend.app.workflows.request_openai_text", return_value=("Model found the authorization claim needs a control comparison.", "test-model")),
        ):
            result = analyze_bug_bounty(main.BUG_BOUNTY_DEMO, allow_ai=True)
        self.assertEqual(result["mode"], "ai")
        self.assertIn("Model found the authorization claim", result["result"])
        self.assertIn("test-model", result["label"])

    def test_soc_analysis_extracts_iocs_and_timeline_without_confirmation(self) -> None:
        request = SocAnalyzeRequest(
            alert_title="Login review", alert_source="export", reported_severity="high",
            raw_logs="2026-10-09T10:00:00Z auth failed user=alice src=203.0.113.2\n"
            "2026-10-09T10:01:00Z auth failed user=alice src=203.0.113.2\n" * 3,
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            result = analyze_soc(request)
        self.assertIn("203.0.113.2", result["indicators"]["ip_addresses"])
        self.assertGreaterEqual(len(result["timeline"]), 2)
        self.assertIn("not a confirmed incident", result["result"].lower())
        self.assertIn("no action was executed", result["result"].lower())

    def test_router_deterministically_classifies_and_routes_to_backend_workflow(self) -> None:
        self.assertEqual(classify_command("Analyze this CTF challenge"), "CTF")
        self.assertEqual(classify_command("Investigate suspicious authentication logs"), "SOC")
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            result = route_command("Analyze this CTF challenge: ELF output strings found", "auto")
        self.assertEqual(result["agent"], "ctf")
        self.assertEqual(result["workflow_path"], "/api/ctf/analyze")
        self.assertIn("local rule-based", result["result"].lower())
        with self.assertRaises(ValidationError):
            RouterRequest(command=" ")

    def test_investigation_and_report_create_list_export_delete(self) -> None:
        created = database.create_investigation(
            title="Sample SOC alert", agent="soc", input_data={"raw_logs": "sample"},
            result_data={"result": "triage summary", "report_markdown": "# Sample SOC alert\n\nTriage summary"},
            severity="Medium triage priority",
        )
        self.assertEqual(len(database.list_investigations(agent="soc")), 1)
        record = database.get_investigation(created["id"])
        self.assertEqual(record["result"]["result"], "triage summary")
        reports = database.list_reports(agent="soc")
        self.assertEqual(len(reports), 1)
        report = database.get_report(reports[0]["id"])
        self.assertIn("# Sample SOC alert", report["markdown"])
        self.assertTrue(database.delete_investigation(created["id"]))
        self.assertEqual(database.list_investigations(), [])
        self.assertEqual(database.list_reports(), [])

    def test_investigation_storage_redacts_api_secrets(self) -> None:
        secret = "sk-proj-abcdefghijklmnopqrstuv"
        created = database.create_investigation(
            title="Redaction check", agent="ctf",
            input_data={"notes": f"OPENAI_API_KEY={secret}; Bearer abcdefghijklmnopqrstuvwxyz"},
            result_data={"result": f"observed api_key: {secret}"},
        )
        saved = database.get_investigation(created["id"])
        self.assertNotIn(secret, str(saved))
        self.assertIn("[REDACTED]", str(saved))
        report = database.get_report(database.list_reports()[0]["id"])
        self.assertNotIn(secret, str(report))

    def test_overview_uses_persisted_counts_and_clear_removes_data(self) -> None:
        database.create_investigation(title="CTF one", agent="ctf", input_data={}, result_data={"result": "done"})
        metrics = database.overview()
        self.assertEqual(metrics["total_investigations"], 1)
        self.assertEqual(metrics["ctf_investigations"], 1)
        database.clear_local_data()
        self.assertEqual(database.overview()["total_reports"], 0)

    def test_api_handlers_health_demo_and_investigation_crud(self) -> None:
        self.assertEqual(main.health()["database"], "ok")
        self.assertIn("DEMO DATA", main.bug_bounty_demo()["label"])
        self.assertIn("DEMO DATA", main.soc_demo()["label"])
        saved = main.save_investigation(main.InvestigationCreate(
            title="Handler integration sample", agent="ctf", input={"command_input": "strings sample"},
            result={"result": "sample analysis", "report_markdown": "# Handler sample"},
        ))
        self.assertEqual(main.investigation_detail(saved["id"])["title"], "Handler integration sample")
        self.assertEqual(len(main.reports_list()), 1)
        report_id = main.reports_list()[0]["id"]
        self.assertIn("Handler sample", main.report_detail(report_id)["markdown"])
        self.assertEqual(main.investigation_remove(saved["id"]), {"deleted": True})
        self.assertEqual(main.reports_list(), [])


if __name__ == "__main__":
    unittest.main()
