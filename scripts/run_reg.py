"""一键执行 WebUI 等价的单次普通注册，并实时打印完整日志。"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.constants import RoleTag  # noqa: E402
from src.services import EmailServiceType  # noqa: E402
from src.config.settings import get_settings  # noqa: E402
from src.database import crud  # noqa: E402
from src.database.init_db import initialize_database  # noqa: E402
from src.database.session import get_db  # noqa: E402
from src.web.routes.registration import _run_sync_registration_task  # noqa: E402
from src.web.task_manager import task_manager  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="执行一次 WebUI 等价的单次普通注册")
    parser.add_argument(
        "--email-service-type",
        default=EmailServiceType.LUCKMAIL.value,
        choices=[
            EmailServiceType.CATCHALL_POP3.value,
            EmailServiceType.CATCHALL_IMAP.value,
            EmailServiceType.LUCKMAIL.value,
            EmailServiceType.IMAP_MAIL.value,
        ],
        help="邮箱策略，默认 catchall_pop3；保留 catchall_imap / luckmail / imap_mail 便于切回旧链路",
    )
    parser.add_argument(
        "--enable-anyauto-fallback",
        action="store_true",
        help="启用 PR60 anyauto V2 回退流程（默认关闭，避免主链路调试卡太久）",
    )
    args = parser.parse_args()

    initialize_database()
    settings = get_settings()
    # Settings 模型未声明该调试字段，这里直接挂到实例上供 register.py 里的 getattr 读取。
    settings.__dict__["registration_enable_anyauto_fallback"] = bool(args.enable_anyauto_fallback)

    task_uuid = str(uuid.uuid4())
    with get_db() as db:
        crud.create_registration_task(db=db, task_uuid=task_uuid, email_service_id=None, proxy=None)

    print(f"[启动] task_uuid={task_uuid}")
    print(f"[参数] email_service_type={args.email_service_type}, registration_type=普通(child), mode=single")
    print(f"[参数] anyauto_fallback={'on' if args.enable_anyauto_fallback else 'off'}")

    run_error: list[str] = []

    def _worker() -> None:
        try:
            _run_sync_registration_task(
                task_uuid=task_uuid,
                email_service_type=args.email_service_type,
                proxy=None,
                email_service_config=None,
                email_service_id=None,
                log_prefix="",
                batch_id="",
                auto_upload_cpa=False,
                cpa_service_ids=[],
                auto_upload_sub2api=False,
                sub2api_service_ids=[],
                auto_upload_tm=False,
                tm_service_ids=[],
                auto_upload_new_api=False,
                new_api_service_ids=[],
                registration_type=RoleTag.CHILD.value,
            )
        except Exception as exc:
            run_error.append(str(exc))

    worker = threading.Thread(target=_worker, name=f"run-reg-{task_uuid[:8]}", daemon=True)
    worker.start()

    printed_count = 0
    while worker.is_alive():
        current_logs = task_manager.get_logs(task_uuid)
        new_logs = current_logs[printed_count:]
        for line in new_logs:
            print(line, flush=True)
        printed_count += len(new_logs)
        time.sleep(0.25)

    worker.join()

    current_logs = task_manager.get_logs(task_uuid)
    new_logs = current_logs[printed_count:]
    for line in new_logs:
        print(line, flush=True)
    printed_count += len(new_logs)

    with get_db() as db:
        task = crud.get_registration_task(db, task_uuid)
        if not task:
            print("[失败] 任务记录不存在")
            return 2

        status = str(task.status or "")
        err = str(task.error_message or (run_error[-1] if run_error else ""))
        logs = str(task.logs or "")
        result = task.result if isinstance(task.result, dict) else {}

    out_path = ROOT / "artifacts" / f"run_reg_{task_uuid}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "task_uuid": task_uuid,
                "status": status,
                "error_message": err,
                "result": result,
                "logs": logs.splitlines() if logs else [],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"[完成] status={status}")
    print(f"[结果] {out_path}")
    if err:
        print(f"[错误] {err}")

    return 0 if status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
