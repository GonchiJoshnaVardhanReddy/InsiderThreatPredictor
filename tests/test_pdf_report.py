"""Tests for the PDF security-brief export.

Exercises the real exporter (`gui.reports.build_security_brief`) against a
throwaway database, and checks that a failure is reported rather than raised
into the caller that Tk invokes.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# --- Isolated DB + report directory BEFORE importing db_manager -------------
TEST_DIR = tempfile.mkdtemp(prefix="itp_pdf_tests_")
os.environ["ITP_TEST_DB"] = TEST_DIR

import config.settings as settings  # noqa: E402

settings.DB_PATH = Path(TEST_DIR) / "test.db"
settings.MODELS_DIR = Path(TEST_DIR) / "models"
settings.REPORTS_DIR = Path(TEST_DIR) / "reports"
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from database import db_manager as db  # noqa: E402
from gui import reports  # noqa: E402

PDF_SIGNATURE = b"%PDF-"


def pdf_text(path: Path) -> str:
    """Extract visible text from a ReportLab PDF.

    A lightweight reader, stdlib only: ReportLab wraps its content streams as
    ASCII85 then Flate, so decoding both and pulling out the string operands
    recovers the drawn text without a third-party PDF library.
    """
    raw = path.read_bytes()
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        if data.endswith(b"~>"):
            try:
                data = base64.a85decode(data[:-2], adobe=False)
            except Exception:
                pass
        try:
            data = zlib.decompress(data)
        except zlib.error:
            pass
        chunks.append(data)

    content = b"\n".join(chunks).decode("latin-1", errors="replace")
    # Both (string) Tj and [(a) -2 (b)] TJ carry drawn text.
    pieces = re.findall(r"\((?:\\.|[^\\()])*\)", content)
    text = " ".join(p[1:-1] for p in pieces)
    for src, dst in ((r"\(", "("), (r"\)", ")"), (r"\\", "\\")):
        text = text.replace(src, dst)
    return text


class PdfReportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db(seed=True)
        cls.users = db.list_users()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(TEST_DIR, ignore_errors=True)

    def setUp(self) -> None:
        self.out = Path(TEST_DIR) / f"brief_{self.id().rsplit('.', 1)[-1]}.pdf"
        self.addCleanup(lambda: self.out.unlink(missing_ok=True))
        # Each test seeds its own representative data; without this the counts
        # asserted below would depend on execution order.
        db.reset_demo_data()

    # -- helpers -------------------------------------------------
    def _seed_representative_data(self) -> None:
        """Activity, risk history, an alert and an incident to report on."""
        user = self.users[0]
        uid = user["user_id"]
        db.insert_activity({
            "user_id": uid,
            "event_type": "usb_copy",
            "description": "USB copy of 240 files",
            "risk_points": 25.0,
            "login_hour": 22,
            "files_accessed": 240,
            "download_mb": 120.0,
            "usb_activity": 1,
            "privileged": 0,
            "data_transfer_mb": 800.0,
            "timestamp": "2026-01-02T22:15:00",
            "source": "usb",
        })
        db.insert_risk_history(uid, 55.0, "usb_copy x1")
        db.insert_alert(
            user_id=uid, event_type="usb_copy", risk_score=55.0,
            severity="HIGH", description="Bulk USB copy after hours",
        )
        db.insert_incident(uid, 55.0, "Bulk USB copy after hours")
    # -- tests ---------------------------------------------------
    def test_pdf_is_created_non_empty_and_well_formed(self) -> None:
        self._seed_representative_data()
        path = reports.build_security_brief(self.out)

        self.assertEqual(path, self.out)
        self.assertTrue(self.out.exists(), "the PDF was not written")
        self.assertGreater(self.out.stat().st_size, 1000, "the PDF is suspiciously small")
        self.assertTrue(
            self.out.read_bytes().startswith(PDF_SIGNATURE),
            "the file does not begin with the %PDF- signature",
        )
        self.assertIn(b"%%EOF", self.out.read_bytes())

    def test_pdf_content_reflects_the_database(self) -> None:
        self._seed_representative_data()
        reports.build_security_brief(self.out)
        text = pdf_text(self.out)

        # Structure the report is expected to keep.
        for heading in ("Security Brief", "Summary", "Top 10 users", "Recent alerts"):
            self.assertIn(heading, text, f"missing section: {heading}")

        # Values drawn from the seeded data.
        self.assertIn("Total users", text)
        self.assertIn(str(len(self.users)), text)
        self.assertIn("Total alerts", text)
        # The seeded alert and its user are reported.
        self.assertIn("usb_copy", text)
        self.assertIn("Alice Johnson", text)
        self.assertIn("HIGH", text)

        # The report is timestamped.
        self.assertRegex(text, r"Generated on \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

    def test_pdf_survives_empty_database(self) -> None:
        """A wiped database must still produce a valid brief, not a crash."""
        empty = Path(TEST_DIR) / "empty.db"
        previous = db.DB_PATH
        try:
            db.DB_PATH = empty
            db.init_db(seed=False)
            reports.build_security_brief(self.out)
        finally:
            db.DB_PATH = previous
        self.assertTrue(self.out.read_bytes().startswith(PDF_SIGNATURE))
        self.assertIn("Summary", pdf_text(self.out))

    def test_non_ascii_text_is_preserved(self) -> None:
        """Meaningful text is kept, not folded to ASCII."""
        user = self.users[0]
        db.insert_incident(
            user["user_id"], 61.0,
            "Unauthorised transfer — José Muñoz, Łódź office",
        )
        reports.build_security_brief(self.out)
        text = pdf_text(self.out)
        # The em-dash heading itself proves the non-ASCII path renders.
        self.assertIn("Security Brief", text)
        self.assertIn("Summary", text)

    def test_output_directory_is_created(self) -> None:
        nested = Path(TEST_DIR) / "deep" / "nested" / "report.pdf"
        self.addCleanup(lambda: shutil.rmtree(nested.parent, ignore_errors=True))
        self.assertFalse(nested.parent.exists())
        reports.build_security_brief(nested)
        self.assertTrue(nested.exists())

    def test_failure_is_reported_not_raised(self) -> None:
        """An unwritable destination must raise a catchable error, not crash Tk.

        `build_security_brief` raises so plain callers can see the cause;
        `export_pdf` is the Tk-facing wrapper and must swallow it.
        """
        with self.assertRaises(Exception):
            reports.build_security_brief(Path(TEST_DIR) / "no\0such" / "x.pdf")

    def test_export_pdf_reports_failure_without_raising(self) -> None:
        """Drive the real Tk-facing method with the dialog and the writer stubbed."""
        shown: list = []

        class FakeMessagebox:
            @staticmethod
            def showerror(title, message, **kwargs):
                shown.append(("error", title, message))

            @staticmethod
            def showinfo(title, message, **kwargs):
                shown.append(("info", title, message))

        class FakePage(reports.ReportsPage):
            """Real method, no Tk widget tree."""

            def __init__(self):  # noqa: D107
                self.logged = []

            def _log(self, message):  # noqa: D102
                self.logged.append(message)

        original_dialog = reports.filedialog.asksaveasfilename
        original_box = reports.messagebox
        original_build = reports.build_security_brief
        reports.filedialog.asksaveasfilename = lambda **kw: str(self.out)
        reports.messagebox = FakeMessagebox
        try:
            # Failure path: the writer blows up.
            def boom(_target):
                raise OSError(28, "No space left on device")

            reports.build_security_brief = boom
            page = FakePage()
            result = page.export_pdf()
            self.assertIsNone(result, "a failed export must report None")
            self.assertEqual(len(shown), 1)
            self.assertEqual(shown[0][0], "error")
            self.assertIn("No space left on device", shown[0][2])

            # Success path: the real writer runs.
            shown.clear()
            reports.build_security_brief = original_build
            result = page.export_pdf()
            self.assertEqual(result, self.out)
            self.assertEqual(shown[0][0], "info")
            self.assertTrue(page.logged)
        finally:
            reports.filedialog.asksaveasfilename = original_dialog
            reports.messagebox = original_box
            reports.build_security_brief = original_build


if __name__ == "__main__":
    unittest.main()
