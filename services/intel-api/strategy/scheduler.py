import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .aggregator import (
    build_daily_exec_summary,
    build_weekly_brief,
    build_monthly_landscape,
)
from .opencti_client import OpenCTIClient

CFG_PATH = os.getenv("STRATEGY_CONFIG", "/app/strategy/config.yml")


def run_daily():
    client = OpenCTIClient()
    result = build_daily_exec_summary(CFG_PATH)
    report_id = client.create_report(result["report_name"], result["description"], confidence=70)
    print(f"[STRATEGY] Daily report created: {report_id}")
    return {"report_id": report_id, "name": result["report_name"]}


def run_weekly():
    client = OpenCTIClient()
    result = build_weekly_brief(CFG_PATH)
    report_id = client.create_report(result["report_name"], result["description"], confidence=75)
    print(f"[STRATEGY] Weekly report created: {report_id}")
    return {"report_id": report_id, "name": result["report_name"]}


def run_monthly():
    client = OpenCTIClient()
    result = build_monthly_landscape(CFG_PATH, days=30)
    report_id = client.create_report(result["report_name"], result["description"], confidence=80)
    print(f"[STRATEGY] Monthly report created: {report_id}")
    return {"report_id": report_id, "name": result["report_name"]}


def start_scheduler():
    enabled = os.getenv("STRATEGY_ENABLED", "false").lower() == "true"
    if not enabled:
        print("[STRATEGY] disabled")
        return None

    daily_cron = os.getenv("STRATEGY_DAILY_CRON", "0 9 * * *")
    weekly_cron = os.getenv("STRATEGY_WEEKLY_CRON", "0 9 * * 1")
    monthly_cron = os.getenv("STRATEGY_MONTHLY_CRON", "0 9 1 * *")  # 1st of month 09:00
    tz = os.getenv("STRATEGY_TIMEZONE", "Asia/Karachi")

    def parse_5(cron_str: str):
        m, h, dom, mon, dow = cron_str.split()
        return m, h, dom, mon, dow

    d_m, d_h, d_dom, d_mon, d_dow = parse_5(daily_cron)
    w_m, w_h, w_dom, w_mon, w_dow = parse_5(weekly_cron)
    m_m, m_h, m_dom, m_mon, m_dow = parse_5(monthly_cron)

    sched = BackgroundScheduler(timezone=tz)
    sched.add_job(run_daily, CronTrigger(minute=d_m, hour=d_h, day=d_dom, month=d_mon, day_of_week=d_dow))
    sched.add_job(run_weekly, CronTrigger(minute=w_m, hour=w_h, day=w_dom, month=w_mon, day_of_week=w_dow))
    sched.add_job(run_monthly, CronTrigger(minute=m_m, hour=m_h, day=m_dom, month=m_mon, day_of_week=m_dow))

    sched.start()
    print(
        f"[STRATEGY] scheduler started (tz={tz}) "
        f"daily='{daily_cron}' weekly='{weekly_cron}' monthly='{monthly_cron}'"
    )
    return sched
 
