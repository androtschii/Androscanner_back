"""Крестики-нолики — чистая логика игры, без Telegram.

Не имеет отношения к сканеру: просто чтобы было чем заняться, пока
идёт долгий скан (vuln, full и подобные могут идти минутами). Telegram-
обвязка (клавиатура, callback) — в bot.py, здесь только правила игры,
чтобы их можно было проверить без сети.
"""

EMPTY = " "
PLAYER = "X"
BOT = "O"

WIN_LINES = [
    (0, 1, 2), (3, 4, 5), (6, 7, 8),  # горизонтали
    (0, 3, 6), (1, 4, 7), (2, 5, 8),  # вертикали
    (0, 4, 8), (2, 4, 6),             # диагонали
]


def new_board() -> list[str]:
    return [EMPTY] * 9


def winner(board: list[str]) -> str | None:
    for a, b, c in WIN_LINES:
        if board[a] != EMPTY and board[a] == board[b] == board[c]:
            return board[a]
    return None


def is_draw(board: list[str]) -> bool:
    return winner(board) is None and EMPTY not in board


def _line_with_two_and_gap(board: list[str], mark: str) -> int | None:
    for a, b, c in WIN_LINES:
        line = [board[a], board[b], board[c]]
        if line.count(mark) == 2 and line.count(EMPTY) == 1:
            return (a, b, c)[line.index(EMPTY)]
    return None


def bot_move(board: list[str]) -> int | None:
    """Индекс клетки для хода бота (O). None, если свободных клеток нет.

    Порядок приоритета: выиграть, если можно за один ход → заблокировать
    игрока, если он выиграл бы за один ход → центр → угол → что попало.
    Не идеальный минимакс, но не проигрывает по невнимательности —
    для игры между сканами этого достаточно.
    """
    empty = [i for i, c in enumerate(board) if c == EMPTY]
    if not empty:
        return None

    move = _line_with_two_and_gap(board, BOT)
    if move is not None:
        return move

    move = _line_with_two_and_gap(board, PLAYER)
    if move is not None:
        return move

    if board[4] == EMPTY:
        return 4

    for i in (0, 2, 6, 8):
        if board[i] == EMPTY:
            return i

    return empty[0]
