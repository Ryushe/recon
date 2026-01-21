module_name = "Dork, find js files, endpoints and more"
module_key = "2"
cli_name = "secrets"


def register_args(parser):
    parser.add_argument("--project", required=True, help="Project directory (stateful)")
    parser.add_argument("--todo", action="store_true", help="Placeholder")


def run_tui(stdscr, config):
    stdscr.addstr(2, 2, "Use CLI:")
    stdscr.addstr(4, 2, "python main.py secrets --project ./target --todo")
    stdscr.refresh()


def run_cli(args, config):
    print("Secrets module placeholder. Use recon --secrets for SecretFinder integration.")

