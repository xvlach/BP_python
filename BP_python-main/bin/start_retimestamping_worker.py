import sys
from pathlib import Path, PurePath

from archivationsystem.common.yaml_parser import parse_yaml_config
from archivationsystem.retimestamping.retimestamping_worker import run_worker


def raise_system_exit():
    raise SystemExit(
        f"Usage: {sys.argv[0]} (-c | --config) <path to yaml config for"
        " archivation worker>"
    )


def parse_arguments(args):
    if not (len(args) == 2):
        raise_system_exit()
    config_path = None
    if args[0] == "-c" or args[0] == "--config":
        config_path = Path(args[1])
    else:
        raise_system_exit()
    if not isinstance(config_path, PurePath):
        raise_system_exit()
    return config_path


def main():
    """
    takes 1 system arguments:
        -c | --config   => configuration file for worker
    """
    config_path = parse_arguments(sys.argv[1:])
    parsed_config = parse_yaml_config(config_path)
    run_worker(parsed_config)


if __name__ == "__main__":
    main()
