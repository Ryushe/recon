import curses


BANNER = "Ryu's Recon"


def draw_menu(stdscr, modules):
    stdscr.clear()
    stdscr.addstr(1, 2, BANNER, curses.A_BOLD)
    stdscr.addstr(2, 2, "-" * len(BANNER))

    row = 4
    for key in sorted(modules.keys(), key=lambda x: (len(x), x)):
        stdscr.addstr(row, 2, f"[{key}] {modules[key]['name']}")
        row += 1

    row += 1
    stdscr.addstr(row, 2, "[s] Settings")
    row += 1
    stdscr.addstr(row, 2, "[q] Quit")
    stdscr.refresh()


def run_tui(stdscr, modules, config):
    while True:
        draw_menu(stdscr, modules)
        key = stdscr.getkey()

        if key == "q":
            return

        if key == "s":
            stdscr.clear()
            stdscr.addstr(2, 2, "Settings not implemented yet.")
            stdscr.addstr(4, 2, "Press any key to return...")
            stdscr.refresh()
            stdscr.getch()
            continue

        if key in modules and callable(modules[key].get("run_tui")):
            stdscr.clear()
            stdscr.addstr(2, 2, f"Running {modules[key]['name']}...")
            stdscr.refresh()
            modules[key]["run_tui"](stdscr, config)
            stdscr.addstr(4, 2, "Press any key to return...")
            stdscr.refresh()
            stdscr.getch()

