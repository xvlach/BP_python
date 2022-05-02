# Script just for consuming and printing logs
import pika


def listen_logs():
    connection_values = pika.ConnectionParameters(
        host="localhost",
        port="5672",
        virtual_host="archivationsystem",
        credentials=pika.PlainCredentials(
            "ncadmin",
            "ncadmin",
            erase_on_connect=True,
        ),
        ssl_options=None,
    )

    connection = pika.BlockingConnection(connection_values)

    channel = connection.channel()

    def callback_print_message(ch, method, properties, body):
        print(body.decode())

    channel.basic_consume(
        "archivation_system_logging", callback_print_message, auto_ack=True
    )
    channel.start_consuming()


if __name__ == "__main__":
    listen_logs()
