from app.notifications.tictactoe import BOT, EMPTY, PLAYER, bot_move, is_draw, new_board, winner


def test_new_board_is_all_empty():
    assert new_board() == [EMPTY] * 9


def test_winner_none_on_empty_board():
    assert winner(new_board()) is None


def test_winner_detects_row():
    board = new_board()
    board[0] = board[1] = board[2] = PLAYER
    assert winner(board) == PLAYER


def test_winner_detects_column():
    board = new_board()
    board[0] = board[3] = board[6] = BOT
    assert winner(board) == BOT


def test_winner_detects_diagonal():
    board = new_board()
    board[0] = board[4] = board[8] = PLAYER
    assert winner(board) == PLAYER


def test_no_false_positive_on_two_in_a_row():
    board = new_board()
    board[0] = board[1] = PLAYER
    assert winner(board) is None


def test_is_draw_true_when_full_and_no_winner():
    board = [PLAYER, BOT, PLAYER, PLAYER, BOT, BOT, BOT, PLAYER, PLAYER]
    assert winner(board) is None
    assert is_draw(board)


def test_is_draw_false_when_cells_free():
    board = new_board()
    assert not is_draw(board)


def test_is_draw_false_when_someone_won_even_if_full():
    board = [PLAYER, PLAYER, PLAYER, BOT, BOT, PLAYER, PLAYER, BOT, BOT]
    assert winner(board) == PLAYER
    assert not is_draw(board)


def test_bot_takes_winning_move_over_blocking():
    board = new_board()
    board[0] = board[1] = BOT       # бот выигрывает, поставив в 2
    board[3] = board[4] = PLAYER    # игрок тоже выиграл бы, поставив в 5
    assert bot_move(board) == 2


def test_bot_blocks_player_win():
    board = new_board()
    board[0] = board[1] = PLAYER
    move = bot_move(board)
    assert move == 2


def test_bot_prefers_center_when_no_urgency():
    board = new_board()
    board[0] = PLAYER
    assert bot_move(board) == 4


def test_bot_takes_corner_when_center_taken():
    board = new_board()
    board[4] = PLAYER
    assert bot_move(board) in (0, 2, 6, 8)


def test_bot_move_none_on_full_board():
    board = [PLAYER, BOT, PLAYER, PLAYER, BOT, BOT, BOT, PLAYER, PLAYER]
    assert bot_move(board) is None
