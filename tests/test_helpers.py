import pytest
import better_cape_mcp.server as srv


class TestBuildSubmissionData:
    def test_drops_falsy_values(self):
        data = srv._build_submission_data(
            machine="win10", package="", tags=None, priority=0, memory=False
        )
        assert data == {"machine": "win10"}

    def test_converts_bool(self):
        data = srv._build_submission_data(memory=True, enforce_timeout=False)
        assert data == {"memory": "1"}

    def test_converts_int(self):
        data = srv._build_submission_data(priority=3, timeout=120)
        assert data == {"priority": "3", "timeout": "120"}

    def test_keeps_strings(self):
        data = srv._build_submission_data(options="foo=bar", tags="ransomware")
        assert data == {"options": "foo=bar", "tags": "ransomware"}


class TestLeanCapeReport:
    def test_minimal_report(self):
        raw = {"info": {"score": 7}}
        lean = srv.get_lean_cape_report(raw)
        assert lean["score"] == 7
        assert lean["family"] == "Unknown"
        assert lean["high_severity_signatures"] == []

    def test_extracts_family_from_malfamily(self):
        raw = {"malfamily": "TrickBot", "info": {"score": 5}}
        assert srv.get_lean_cape_report(raw)["family"] == "TrickBot"

    def test_extracts_family_from_detections(self):
        raw = {"detections": {"family": "Dridex"}, "info": {"score": 5}}
        assert srv.get_lean_cape_report(raw)["family"] == "Dridex"

    def test_filters_signatures_by_severity(self):
        raw = {
            "info": {"score": 5},
            "signatures": [
                {"name": "low", "description": "x", "severity": 1},
                {"name": "high", "description": "y", "severity": 3},
                {"name": "critical", "description": "z", "severity": 5},
            ],
        }
        sigs = srv.get_lean_cape_report(raw)["high_severity_signatures"]
        assert len(sigs) == 2
        assert {s["name"] for s in sigs} == {"high", "critical"}

    def test_network_domains(self):
        raw = {"info": {"score": 0}, "network": {"domains": [{"domain": "evil.com"}]}}
        assert srv.get_lean_cape_report(raw)["network"]["domains"] == ["evil.com"]

    def test_network_http_uris(self):
        raw = {"info": {"score": 0}, "network": {"http": [{"uri": "http://evil.com/c2"}]}}
        assert srv.get_lean_cape_report(raw)["network"]["http_uris"] == ["http://evil.com/c2"]

    def test_indicators_mutexes_and_commands(self):
        raw = {
            "info": {"score": 0},
            "behavior": {"summary": {"mutexes": ["mut1"], "executed_commands": ["cmd1"]}},
        }
        indicators = srv.get_lean_cape_report(raw)["indicators"]
        assert indicators["mutexes"] == ["mut1"]
        assert indicators["commands"] == ["cmd1"]

    def test_handles_missing_behavior_summary(self):
        raw = {"info": {"score": 0}, "behavior": {}}
        indicators = srv.get_lean_cape_report(raw)["indicators"]
        assert indicators["mutexes"] == []
        assert indicators["commands"] == []


class TestApplyLeanReport:
    def test_dict_error_false_with_list_data(self):
        result = srv._apply_lean_report(
            {"error": False, "data": [{"info": {"score": 5}, "malfamily": "X"}]}
        )
        assert result["data"][0]["family"] == "X"

    def test_dict_error_false_with_dict_data(self):
        result = srv._apply_lean_report(
            {"error": False, "data": {"info": {"score": 5}, "malfamily": "Y"}}
        )
        assert result["data"]["family"] == "Y"

    def test_dict_with_info_key_direct(self):
        result = srv._apply_lean_report({"info": {"score": 3}, "malfamily": "Z"})
        assert result["family"] == "Z"

    def test_list_input(self):
        result = srv._apply_lean_report([{"info": {"score": 1}, "malfamily": "A"}])
        assert result[0]["family"] == "A"

    def test_error_dict_passthrough(self):
        err = {"error": True, "message": "boom"}
        assert srv._apply_lean_report(err) == err

    def test_non_dict_passthrough(self):
        assert srv._apply_lean_report("hello") == "hello"
