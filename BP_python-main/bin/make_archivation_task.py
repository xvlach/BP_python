import json

# import socket - was unused
import sys
from pathlib import Path, PurePath
from uuid import uuid4

import pika
from archivationsystem.common.yaml_parser import parse_yaml_config
from archivationsystem.rabbitmq_connection.task_consumer import ConnectionMaker


def format_task_message(file_path, owner):
    task_message = {
        "task": "archive",
        "file_path": str(file_path),
        "owner_name": str(owner),
    }
    return json.dumps(task_message)


def make_task(config, task_message):
    c_maker = ConnectionMaker(config.get("rabbitmq_connection"))
    connection = c_maker.make_connection()
    channel = connection.channel()
    channel.basic_publish(
        exchange="",
        routing_key=config["rabbitmq_info"].get("task_queue"),
        properties=pika.BasicProperties(correlation_id=str(uuid4())),
        body=task_message,
    )
    print(
        "Message published to: ",
        config["rabbitmq_info"].get("task_queue"),
        task_message,
    )
    channel.close()


def raise_system_exit():
    raise SystemExit(
        f"Usage: {sys.argv[0]} (-c | --config) <path to yaml config for"
        " Rabbitmq connection> (-fp | --filePath) <path to file which will be"
        " archived> (-o | --owner) <owner name>"
    )


def parse_arguments(args):
    if not (len(args) == 6):
        raise_system_exit()

    config_path = None
    file_path = None
    owner = None
    if args[0] == "-c" or args[0] == "--config":
        config_path = Path(args[1])
    if args[2] == "-fp" or args[2] == "--filePath":
        file_path = Path(args[3])
    if args[2] == "-c" or args[2] == "--config":
        config_path = Path(args[3])
    if args[0] == "-fp" or args[0] == "--filePath":
        file_path = Path(args[1])
    if args[4] == "-o" or args[4] == "--owner":
        owner = str(args[5])
    if not (
        isinstance(config_path, PurePath)
        or isinstance(file_path, PurePath)
        or isinstance(owner, str)
    ):
        raise_system_exit()
    return config_path, file_path, owner


def main():
    """
    takes 2 system arguments:
        -c | --config   => configuration file path for connection to Rabbitmq
        -fp | --filePath     => file path for archivation
    """
    config_path, file_path, owner = parse_arguments(sys.argv[1:])

    make_task(
        parse_yaml_config(config_path), format_task_message(file_path, owner)
    )


if __name__ == "__main__":
    main()
