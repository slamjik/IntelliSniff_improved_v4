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
}

# Перевод payload ключей
PAYLOAD_TRANSLATION = {
    "records": "Количество записей",
    "duration": "Длительность",
    "msg": "Сообщение",
}


# Перевод результата на русский
def translate_result(result: Optional[str]) -> str:
    if not result:
        return "—"
    result = result.lower()
    if result in ("success", "ok"):
        return "[green]Успех[/green]"
    if result in ("error", "fail", "failed"):
        return "[red]Ошибка[/red]"
    return result


def format_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return "[grey50]—[/grey50]"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def show_session_details(session: SessionLog):
    """Показывает детальную информацию о сессии."""
    tree = Tree(
        f"[bold cyan]Сессия #{session.id}[/bold cyan]   :  "
        f"[yellow]{session.user}[/yellow]"
    )

    # Основная часть
    info = tree.add("[bold white]Информация[/bold white]")
    info.add(f"[green]Начало:[/green]  {format_dt(session.started_at)}")
    info.add(f"[green]Окончание:[/green] {format_dt(session.finished_at)}")
    info.add(f"[green]Результат:[/green]   {translate_result(session.result)}")

    # Детали сессии
    if session.details:
        det = info.add("[green]Детали:[/green]")
        for k, v in session.details.items():
            det.add(f"[cyan]{k}[/cyan]: {v}")

    # Действия
    actions_root = tree.add("[bold white]Действия[/bold white]")

    if not session.actions:
        actions_root.add("[grey50]Действия отсутствуют[/grey50]")
    else:
        # сортируем по времени
        actions_sorted = sorted(session.actions, key=lambda a: a.created_at)

        for action in actions_sorted:

            # переводим имя действия
            action_name = ACTION_NAMES.get(action.name, action.name)

            node = actions_root.add(
                f"[magenta]{action_name}[/magenta]  "
                f"([blue]{format_dt(action.created_at)}[/blue])"
            )

            # payload
            if action.payload:
                for key, val in action.payload.items():
                    key_ru = PAYLOAD_TRANSLATION.get(key, key)
                    node.add(f"[cyan]{key_ru}[/cyan]: {val}")
            else:
                node.add("[grey50]Нет данных[/grey50]")

    console.print(tree)
    console.print("\n" + "-" * 80 + "\n")


def list_sessions(limit: int = 10):
    """Показывает последние N сессий."""
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

    # Таблица сводки
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
