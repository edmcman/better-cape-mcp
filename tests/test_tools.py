import asyncio
import pytest
import better_cape_mcp.server as srv


def _list_tools():
    return asyncio.run(srv.mcp.list_tools())


@pytest.fixture
def tool_names():
    return _list_tools()


class TestToolSurface:
    def test_expected_tool_count(self, tool_names):
        assert len(tool_names) == 36

    def test_submit_file_registered(self, tool_names):
        assert any(t.name == "submit_file" for t in tool_names)

    def test_submit_url_registered(self, tool_names):
        assert any(t.name == "submit_url" for t in tool_names)

    def test_search_task_registered(self, tool_names):
        assert any(t.name == "search_task" for t in tool_names)

    def test_extended_search_registered(self, tool_names):
        assert any(t.name == "extended_search" for t in tool_names)

    def test_get_search_info_registered(self, tool_names):
        assert any(t.name == "get_search_info" for t in tool_names)

    def test_list_tasks_registered(self, tool_names):
        assert any(t.name == "list_tasks" for t in tool_names)

    def test_view_task_registered(self, tool_names):
        assert any(t.name == "view_task" for t in tool_names)

    def test_reschedule_task_registered(self, tool_names):
        assert any(t.name == "reschedule_task" for t in tool_names)

    def test_reprocess_task_registered(self, tool_names):
        assert any(t.name == "reprocess_task" for t in tool_names)

    def test_get_task_status_registered(self, tool_names):
        assert any(t.name == "get_task_status" for t in tool_names)

    def test_get_latest_tasks_registered(self, tool_names):
        assert any(t.name == "get_latest_tasks" for t in tool_names)

    def test_get_statistics_registered(self, tool_names):
        assert any(t.name == "get_statistics" for t in tool_names)

    def test_get_task_report_registered(self, tool_names):
        assert any(t.name == "get_task_report" for t in tool_names)

    def test_get_task_iocs_registered(self, tool_names):
        assert any(t.name == "get_task_iocs" for t in tool_names)

    def test_get_task_config_registered(self, tool_names):
        assert any(t.name == "get_task_config" for t in tool_names)

    def test_download_task_screenshot_registered(self, tool_names):
        assert any(t.name == "download_task_screenshot" for t in tool_names)

    def test_download_task_pcap_registered(self, tool_names):
        assert any(t.name == "download_task_pcap" for t in tool_names)

    def test_download_task_tlspcap_registered(self, tool_names):
        assert any(t.name == "download_task_tlspcap" for t in tool_names)

    def test_download_task_evtx_registered(self, tool_names):
        assert any(t.name == "download_task_evtx" for t in tool_names)

    def test_download_task_dropped_registered(self, tool_names):
        assert any(t.name == "download_task_dropped" for t in tool_names)

    def test_download_self_extracted_files_registered(self, tool_names):
        assert any(t.name == "download_self_extracted_files" for t in tool_names)

    def test_download_task_surifile_registered(self, tool_names):
        assert any(t.name == "download_task_surifile" for t in tool_names)

    def test_download_task_mitmdump_registered(self, tool_names):
        assert any(t.name == "download_task_mitmdump" for t in tool_names)

    def test_download_task_payloadfiles_registered(self, tool_names):
        assert any(t.name == "download_task_payloadfiles" for t in tool_names)

    def test_download_task_procdumpfiles_registered(self, tool_names):
        assert any(t.name == "download_task_procdumpfiles" for t in tool_names)

    def test_download_task_procmemory_registered(self, tool_names):
        assert any(t.name == "download_task_procmemory" for t in tool_names)

    def test_download_task_fullmemory_registered(self, tool_names):
        assert any(t.name == "download_task_fullmemory" for t in tool_names)

    def test_view_file_registered(self, tool_names):
        assert any(t.name == "view_file" for t in tool_names)

    def test_download_sample_registered(self, tool_names):
        assert any(t.name == "download_sample" for t in tool_names)

    def test_list_machines_registered(self, tool_names):
        assert any(t.name == "list_machines" for t in tool_names)

    def test_view_machine_registered(self, tool_names):
        assert any(t.name == "view_machine" for t in tool_names)

    def test_list_exitnodes_registered(self, tool_names):
        assert any(t.name == "list_exitnodes" for t in tool_names)

    def test_get_cuckoo_status_registered(self, tool_names):
        assert any(t.name == "get_cuckoo_status" for t in tool_names)

    def test_verify_auth_registered(self, tool_names):
        assert any(t.name == "verify_auth" for t in tool_names)
