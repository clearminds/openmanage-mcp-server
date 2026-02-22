"""OpenManage Enterprise MCP Server — FastMCP tools for Dell OME management."""

import argparse
import logging
import logging.config
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP

from clr_openmanage_mcp.config import Settings
from clr_openmanage_mcp.ome_client import (
from clr_openmanage_mcp.middleware import ToolValidationMiddleware
    HEALTH_NAMES,
    SEVERITY_MAP,
    STATUS_MAP,
    OmeClient,
)

mcp = FastMCP("OpenManage Enterprise")
mcp.add_middleware(ToolValidationMiddleware())
_client: OmeClient | None = None

WRITE_TOOLS = ["ome_alert_ack", "ome_alert_ack_all"]


# ── Helper: build OData filter ───────────────────────────────────────


def _build_alert_filter(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> str | None:
    """Build OData $filter string from severity/category/status.

    Args:
        severity: Severity level (critical, warning, info, or normal).
        category: SubCategoryName value (e.g. "Warranty").
        status: Acknowledgement status (unack or ack).

    Returns:
        An OData ``$filter`` string combining all provided filters with
        ``and``, or ``None`` if no filters are specified.
    """
    parts = []
    if severity:
        sev_val = SEVERITY_MAP.get(severity.lower())
        if sev_val:
            parts.append(f"SeverityType eq {sev_val}")
    if category:
        parts.append(f"SubCategoryName eq '{category}'")
    if status:
        stat_val = STATUS_MAP.get(status.lower())
        if stat_val:
            parts.append(f"StatusType eq {stat_val}")
    return " and ".join(parts) if parts else None


# ── System tools ─────────────────────────────────────────────────────


@mcp.tool
def ome_version() -> dict[str, Any]:
    """Get OME version, build info, and operation status.

    Returns version, build number, build date, and current operation status
    of the OpenManage Enterprise appliance.
    """
    return _client.get("/api/ApplicationService/Info")


# ── Device tools ─────────────────────────────────────────────────────


@mcp.tool
def ome_list_devices(top: int | None = None) -> list[dict[str, Any]]:
    """List all managed devices in OpenManage Enterprise.

    Args:
        top: Limit number of results (OData $top).

    Returns list of devices with Id, DeviceName, Model, DeviceServiceTag,
    PowerState, and ConnectionState.
    """
    data = _client.get("/api/DeviceService/Devices", top=top)
    rows = data.get("value", [])
    return [
        {
            "Id": d.get("Id"),
            "DeviceName": d.get("DeviceName"),
            "Model": d.get("Model"),
            "DeviceServiceTag": d.get("DeviceServiceTag"),
            "PowerState": d.get("PowerState"),
            "ConnectionState": d.get("ConnectionState"),
            "Status": d.get("Status"),
        }
        for d in rows
    ]


@mcp.tool
def ome_get_device(device_id: int) -> dict[str, Any]:
    """Get full detail for a single device by ID.

    Args:
        device_id: The OME device ID (integer).

    Returns complete device information including hardware, firmware,
    network, and management details.
    """
    return _client.get(f"/api/DeviceService/Devices({device_id})")


@mcp.tool
def ome_device_health() -> dict[str, Any]:
    """Get aggregate device health summary — count by status.

    Returns a summary of how many devices are in each health status
    (Normal, Warning, Critical, Unknown, Information).
    """
    data = _client.get("/api/DeviceService/Devices")
    rows = data.get("value", [])

    counts = Counter()
    for d in rows:
        status = d.get("Status", 2000)
        counts[status] += 1

    summary = {}
    for code, count in sorted(counts.items()):
        name = HEALTH_NAMES.get(code, f"Status_{code}")
        summary[name] = count

    return {"total_devices": len(rows), "health": summary}


# ── Alert tools ──────────────────────────────────────────────────────


@mcp.tool
def ome_list_alerts(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    top: int | None = None,
) -> list[dict[str, Any]]:
    """List alerts, newest first, with optional filters.

    Args:
        severity: Filter by severity — critical, warning, info, or normal.
        category: Filter by SubCategoryName (e.g. "Warranty").
        status: Filter by acknowledgement status — unack or ack.
        top: Limit number of results.

    Returns list of alerts with Id, severity, status, device, timestamp, message.
    """
    params = {"$orderby": "TimeStamp desc"}
    odata_filter = _build_alert_filter(severity, category, status)
    if odata_filter:
        params["$filter"] = odata_filter

    data = _client.get("/api/AlertService/Alerts", params=params, top=top)
    rows = data.get("value", [])

    return [
        {
            "Id": a.get("Id"),
            "SeverityName": a.get("SeverityName"),
            "StatusName": a.get("StatusName"),
            "AlertDeviceName": a.get("AlertDeviceName"),
            "TimeStamp": a.get("TimeStamp"),
            "Message": a.get("Message"),
            "SubCategoryName": a.get("SubCategoryName"),
        }
        for a in rows
    ]


@mcp.tool
def ome_get_alert(alert_id: int) -> dict[str, Any]:
    """Get full detail for a single alert by ID.

    Args:
        alert_id: The OME alert ID (integer).

    Returns complete alert information.
    """
    return _client.get(f"/api/AlertService/Alerts({alert_id})")


@mcp.tool
def ome_alert_count() -> dict[str, Any]:
    """Get alert count aggregated by severity.

    Returns total alert count and breakdown by severity level
    (Critical, Warning, Normal, Info).
    """
    data = _client.get("/api/AlertService/Alerts")
    rows = data.get("value", [])

    counts = Counter()
    for a in rows:
        sev = a.get("SeverityName", "Unknown")
        counts[sev] += 1

    return {"total": len(rows), "by_severity": dict(counts.most_common())}


@mcp.tool
def ome_alert_ack(alert_ids: list[int]) -> dict[str, Any]:
    """Acknowledge one or more alerts by ID.

    This is a non-destructive write operation — it marks alerts as
    acknowledged but does not delete or modify device configuration.

    Args:
        alert_ids: List of alert IDs to acknowledge.

    Returns acknowledgement result with count.
    """
    status_code, body = _client.post(
        "/api/AlertService/Actions/AlertService.Acknowledge",
        {"AlertIds": alert_ids},
    )
    if status_code == 204 or (200 <= status_code < 300):
        return {"acknowledged": len(alert_ids), "alert_ids": alert_ids}
    return {"error": f"HTTP {status_code}", "detail": body}


@mcp.tool
def ome_alert_ack_all(
    severity: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Acknowledge all unacknowledged alerts matching filters.

    Fetches all unack alerts matching the severity/category filters,
    then acknowledges them in batches of 100.

    Args:
        severity: Optional severity filter — critical, warning, info, normal.
        category: Optional category filter (e.g. "Warranty").

    Returns count of acknowledged alerts.
    """
    params = {"$orderby": "TimeStamp desc"}
    odata_filter = _build_alert_filter(severity, category, status="unack")
    if odata_filter:
        params["$filter"] = odata_filter

    data = _client.get("/api/AlertService/Alerts", params=params)
    rows = data.get("value", [])

    if not rows:
        return {
            "acknowledged": 0,
            "message": "No unacknowledged alerts matching filters",
        }

    all_ids = [r["Id"] for r in rows]

    # Batch in groups of 100
    for i in range(0, len(all_ids), 100):
        batch = all_ids[i : i + 100]
        status_code, body = _client.post(
            "/api/AlertService/Actions/AlertService.Acknowledge",
            {"AlertIds": batch},
        )
        if status_code != 204 and not (200 <= status_code < 300):
            return {
                "error": f"Batch failed at offset {i}",
                "status": status_code,
                "detail": body,
            }

    return {"acknowledged": len(all_ids)}


# ── Warranty tools ───────────────────────────────────────────────────


@mcp.tool
def ome_list_warranties(top: int | None = None) -> list[dict[str, Any]]:
    """List all warranty records.

    Args:
        top: Limit number of results.

    Returns list of warranties with device name, model, service tag,
    service level, start/end dates.
    """
    data = _client.get("/api/WarrantyService/Warranties", top=top)
    rows = data.get("value", [])
    return [
        {
            "DeviceName": w.get("DeviceName"),
            "DeviceModel": w.get("DeviceModel"),
            "DeviceIdentifier": w.get("DeviceIdentifier"),
            "ServiceLevelDescription": w.get("ServiceLevelDescription"),
            "StartDate": w.get("StartDate"),
            "EndDate": w.get("EndDate"),
        }
        for w in rows
    ]


@mcp.tool
def ome_warranties_expired() -> list[dict[str, Any]]:
    """List warranties that have expired (past EndDate).

    Client-side date filter since OME doesn't support date comparison
    in OData $filter for warranty endpoints.

    Returns only expired warranty records.
    """
    data = _client.get("/api/WarrantyService/Warranties")
    rows = data.get("value", [])
    now = datetime.now(timezone.utc)

    expired = []
    for w in rows:
        end_date_str = w.get("EndDate", "")
        if not end_date_str:
            continue
        try:
            clean = end_date_str.replace("Z", "+00:00")
            if "T" in clean:
                end_date = datetime.fromisoformat(clean)
            else:
                end_date = datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)
            if end_date < now:
                expired.append(
                    {
                        "DeviceName": w.get("DeviceName"),
                        "DeviceModel": w.get("DeviceModel"),
                        "DeviceIdentifier": w.get("DeviceIdentifier"),
                        "ServiceLevelDescription": w.get("ServiceLevelDescription"),
                        "StartDate": w.get("StartDate"),
                        "EndDate": w.get("EndDate"),
                    }
                )
        except (ValueError, TypeError):
            continue

    return expired


# ── Group, Job, Policy, Firmware tools ───────────────────────────────


@mcp.tool
def ome_list_groups(top: int | None = None) -> list[dict[str, Any]]:
    """List device groups.

    Args:
        top: Limit number of results.

    Returns list of groups with Id, Name, TypeId, MembershipTypeId.
    """
    data = _client.get("/api/GroupService/Groups", top=top)
    rows = data.get("value", [])
    return [
        {
            "Id": g.get("Id"),
            "Name": g.get("Name"),
            "TypeId": g.get("TypeId"),
            "MembershipTypeId": g.get("MembershipTypeId"),
        }
        for g in rows
    ]


@mcp.tool
def ome_list_jobs(top: int | None = None) -> list[dict[str, Any]]:
    """List jobs, most recent first.

    OME Jobs API does not support $orderby, so results are sorted
    client-side by LastRun descending. LastRunStatus is flattened
    from a nested object to its Name string.

    Args:
        top: Limit number of results.

    Returns list of jobs with Id, JobName, LastRunStatus, LastRun.
    """
    data = _client.get("/api/JobService/Jobs", top=top)
    rows = data.get("value", [])

    result = []
    for j in rows:
        lrs = j.get("LastRunStatus")
        status_name = (
            lrs.get("Name", str(lrs.get("Id", "")))
            if isinstance(lrs, dict)
            else str(lrs)
        )
        result.append(
            {
                "Id": j.get("Id"),
                "JobName": j.get("JobName"),
                "LastRunStatus": status_name,
                "LastRun": j.get("LastRun"),
            }
        )

    # Sort by LastRun descending (client-side)
    result.sort(key=lambda r: r.get("LastRun") or "", reverse=True)
    return result


@mcp.tool
def ome_list_policies(top: int | None = None) -> list[dict[str, Any]]:
    """List alert policies.

    Args:
        top: Limit number of results.

    Returns list of policies with Id, Name, Enabled, Description.
    """
    data = _client.get("/api/AlertService/AlertPolicies", top=top)
    rows = data.get("value", [])
    return [
        {
            "Id": p.get("Id"),
            "Name": p.get("Name"),
            "Enabled": p.get("Enabled"),
            "Description": p.get("Description"),
        }
        for p in rows
    ]


@mcp.tool
def ome_list_firmware(top: int | None = None) -> list[dict[str, Any]]:
    """List firmware compliance baselines.

    Args:
        top: Limit number of results.

    Returns list of baselines with Id, Name, and ComplianceSummary.
    """
    data = _client.get("/api/UpdateService/Baselines", top=top)
    rows = data.get("value", [])
    return [
        {
            "Id": b.get("Id"),
            "Name": b.get("Name"),
            "ComplianceSummary": b.get("ComplianceSummary"),
        }
        for b in rows
    ]


# ── Main entry point ─────────────────────────────────────────────────


def main() -> None:
    """Main entry point for the OpenManage Enterprise MCP server."""
    global _client

    settings = Settings()

    parser = argparse.ArgumentParser(description="OpenManage Enterprise MCP Server")
    parser.add_argument(
        "--transport", type=str, choices=["stdio", "http"], default=None
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("--ome-host", type=str, default=None)
    parser.add_argument("--ome-username", type=str, default=None)
    parser.add_argument("--ome-password", type=str, default=None)
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Run in read-only mode (hide write tools)",
    )
    args = parser.parse_args()

    creds = settings.load_credentials()

    # CLI args override everything
    transport = args.transport or settings.ome_transport
    log_level = args.log_level or settings.ome_log_level
    ome_host = args.ome_host or creds.get("host", "")
    ome_username = args.ome_username or creds.get("username", "")
    ome_password = args.ome_password or creds.get("password", "")

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "console": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "console",
                    "stream": "ext://sys.stderr",
                }
            },
            "root": {"level": log_level, "handlers": ["console"]},
        }
    )

    logger = logging.getLogger(__name__)

    if not ome_username or not ome_password:
        logger.error("OME_USERNAME and OME_PASSWORD are required")
        sys.exit(1)

    logger.info("Connecting to OME at %s", ome_host)
    _client = OmeClient(ome_host, ome_username, ome_password)

    read_only = args.read_only if args.read_only is not None else settings.ome_read_only
    if read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp.remove_tool(name)
        logger.info("Read-only mode: %d write tools removed", len(WRITE_TOOLS))

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.run(transport="http", host=args.host, port=args.port)
    except Exception as e:
        logger.error("Failed to start MCP server: %s", e)
        sys.exit(1)
    finally:
        _client.close()


if __name__ == "__main__":
    main()
