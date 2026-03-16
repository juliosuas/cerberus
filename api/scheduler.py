"""APScheduler-based periodic scan scheduler."""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from core.config import Config
from api import db
from core.scanner import InfrastructureScanner
from core.monitor import ContinuousMonitor
from core.compliance import ComplianceChecker
from core.ai_advisor import AIAdvisor

logger = logging.getLogger("cerberus.scheduler")


def run_scan_for_target(target_id: int):
    """Run a full scan for a single target."""
    target = db.get_target(target_id)
    if not target:
        logger.error(f"Target {target_id} not found")
        return

    domain = target["domain"]
    logger.info(f"Starting scheduled scan for {domain}")

    # Create scan record
    scan_id = db.create_scan(target_id, "full")

    try:
        # Infrastructure scan
        scanner = InfrastructureScanner(domain)
        scan_results = scanner.run_all()

        # Save findings
        for finding in scan_results.get("findings", []):
            db.create_finding(
                scan_id=scan_id,
                target_id=target_id,
                severity=finding.get("severity", "low"),
                category=finding.get("category", "unknown"),
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                remediation=finding.get("remediation", ""),
            )

        # Compliance check
        checker = ComplianceChecker(domain, scan_results)
        compliance_results = checker.run_all()

        for framework, data in compliance_results.get("frameworks", {}).items():
            db.save_compliance_score(
                target_id=target_id,
                scan_id=scan_id,
                framework=framework,
                score=data.get("score", 0),
                grade=data.get("grade", "F"),
                details=data,
            )

        # Update scan status
        db.update_scan(scan_id, "completed", {
            "scan": scan_results,
            "compliance": compliance_results,
        })

        logger.info(f"Scan completed for {domain}: {len(scan_results.get('findings', []))} findings")

    except Exception as e:
        logger.error(f"Scan failed for {domain}: {e}")
        db.update_scan(scan_id, "failed", {"error": str(e)})


def run_all_scans():
    """Run scans for all targets."""
    targets = db.get_targets()
    for target in targets:
        try:
            run_scan_for_target(target["id"])
        except Exception as e:
            logger.error(f"Scan failed for target {target['id']}: {e}")


def start_scheduler():
    """Start the background scheduler."""
    scheduler = BackgroundScheduler()
    interval_hours = Config.SCAN_INTERVAL_HOURS

    scheduler.add_job(
        run_all_scans,
        trigger=IntervalTrigger(hours=interval_hours),
        id="periodic_scan",
        name=f"Run all scans every {interval_hours} hours",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(f"Scheduler started: scans every {interval_hours} hours")
    return scheduler
