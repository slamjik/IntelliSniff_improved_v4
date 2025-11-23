from __future__ import annotations

from datetime import datetime
from typing import Optional

from rich import box
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from sqlalchemy.orm import joinedload

from app.db import SessionLocal
from app.models import ActionLog, SessionLog

console = Console()

# Перевод английских action-имен на русский
ACTION_NAMES = {
    "load_data": "Загрузка данных",
    "analyze": "Анализ данных",
    "ping": "Проверочный запрос",
    "capture_started": "Запуск захвата",
    "capture_stopped": "Остановка захвата",
    "sniffer_started": "Запуск сниффера",
    "flow_emitted": "Флоу",
    "streaming_stopped": "Остановка стриминга",
}

# Перевод payload ключей на русский
PAYLOAD_TRANSLATION = {
    "records": "Количество записей",
    "duration": "Длительность (сек)",
    "msg": "Сообщение",

    "bytes": "Байты",
    "packets": "Пакеты",
    "proto": "Протокол",
    "src": "Источник",
    "dst": "Назначение",
    "score": "Оценка",
    "label": "Метка",
}

# Перевод ключей session.details
DETAIL_TRANSLATION = {
    "total_bytes": "Всего байт",
    "total_packets": "Всего пакетов",
    "flows_processed": "Флоу обработано",
    "attacks_detected": "Обнаружено атак",
    "duration_seconds": "Длительность",
    "avg_bytes_per_flow": "Средний размер флоу (байт)",
    "avg_packets_per_flow": "Среднее число пакетов на флоу",
}


def humanize_value(key: str, value):
    """Красивое форматирование чисел, байтов и длительности."""
    # Человеческий вывод времени
    if key == "duration_seconds":
        sec = float(value)
        minutes = int(sec // 60)
        seconds = sec % 60
        return f"{sec:.1f} сек ({minutes} мин {seconds:.0f} сек)"

    # Форматирование чисел с пробелами
    if isinstance(value, (int, float)):
        if abs(value) >= 1000:
            return f"{value:,.0f}".replace(",", " ")
        else:
            return str(value)

    return str(value)


def translate_result(result: Optional[str]) -> str:
    if not result:
        return "—"
    r = result.lower()
    if r in ("success", "ok"):
        return "[green]Успех[/green]"
    if r in ("error", "fail", "failed"):
        return "[red]Ошибка[/red]"
    return result


def format_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return "[grey50]—[/grey50]"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def shorten(s: str, max_len=40):
    if not s:
        return s
    s = str(s)
    return s if len(s) <= max_len else s[:max_len] + "…"


def show_session_details(session: SessionLog):
    """Красивый, компактный вывод подробных данных по сессии."""
    tree = Tree(
        f"[bold cyan]Сессия #{session.id}[/bold cyan]   :  "
        f"[yellow]{session.user}[/yellow]"
    )

    info = tree.add("[bold white]Информация[/bold white]")
    info.add(f"[green]Начало:[/green]  {format_dt(session.started_at)}")
    info.add(f"[green]Окончание:[/green] {format_dt(session.finished_at)}")
    info.add(f"[green]Результат:[/green]   {translate_result(session.result)}")

    # Детали сессии — переводим + форматируем
    if session.details:
        det = info.add("[green]Детали:[/green]")
        for k, v in session.details.items():
            key_ru = DETAIL_TRANSLATION.get(k, k)
            det.add(f"[cyan]{key_ru}[/cyan]: {humanize_value(k, v)}")

    # Блок действий
    actions_root = tree.add("[bold white]Действия[/bold white]")

    if not session.actions:
        actions_root.add("[grey50]Нет действий[/grey50]")
    else:
        actions_sorted = sorted(session.actions, key=lambda a: a.created_at)

        # отдельный блок для flow_emitted
        flow_events = [a for a in actions_sorted if a.name == "flow_emitted"]
        normal_actions = [a for a in actions_sorted if a.name != "flow_emitted"]

        # обычные действия
        for action in normal_actions:
            action_name = ACTION_NAMES.get(action.name, action.name)
            node = actions_root.add(
                f"[magenta]{action_name}[/magenta]  "
                f"([blue]{format_dt(action.created_at)}[/blue])"
            )
            if action.payload:
                for k, v in action.payload.items():
                    k_ru = PAYLOAD_TRANSLATION.get(k, k)
                    node.add(f"  [cyan]{k_ru}[/cyan]: {shorten(v)}")
            else:
                node.add("[grey50]Нет данных[/grey50]")

        # компактный блок для флоу
        if flow_events:
            flows_node = actions_root.add(
                f"[bold magenta]Флоу (всего {len(flow_events)})[/bold magenta]"
            )

            # показываем только последние 5
            for action in flow_events[-5:]:
                d = action.payload or {}
                flows_node.add(
                    f"[blue]{format_dt(action.created_at)}[/blue]  "
                    f"{d.get('bytes', '?')} байт, "
                    f"{d.get('packets', '?')} пакетов → "
                    f"{shorten(d.get('src', '?'))} → {shorten(d.get('dst', '?'))}"
                )

            if len(flow_events) > 5:
                flows_node.add(
                    f"[grey50]... отображены последние 5 из {len(flow_events)} ...[/grey50]"
                )

    console.print(tree)
    console.print("\n" + "-" * 80 + "\n")


def list_sessions(limit: int = 10):
    """Вывод последних N сессий."""
    with SessionLocal() as db:
        sessions = (
            db.query(SessionLog)
            .options(joinedload(SessionLog.actions))
            .order_by(SessionLog.started_at.desc())
            .limit(limit)
            .all()
        )

    if not sessions:
        console.print("[red]Сессии не найдены[/red]")
        return

    # таблица
    table = Table(title="Последние сессии", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Пользователь", style="yellow")
    table.add_column("Начало", style="green")
    table.add_column("Окончание", style="green")
    table.add_column("Результат", style="bold")

    for s in sessions:
        table.add_row(
            str(s.id),
            s.user,
            format_dt(s.started_at),
            format_dt(s.finished_at),
            translate_result(s.result),
        )

    console.print(table)
    console.print("\n[bold underline]Подробно:[/bold underline]\n")

    for s in sessions:
        show_session_details(s)


if __name__ == "__main__":
    list_sessions(limit=10)
