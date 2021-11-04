from enum import IntEnum
import socket, threading


BUFF_SIZE = 1024


class Phase(IntEnum):
    NIGHT = 0
    DAY = 1
    VOTE = 2


class Role(IntEnum):
    CITIZEN = 0
    DOCTOR = 1
    DETECTIVE = 2
    MAFIA = 3
    GODFATHER = 4
    STORYTELLER = 5

    def __str__(self) -> str:
        return super().__str__()


class Team(IntEnum):
    MAFIA = 1
    STORYTELLER = 0
    CITIZEN = -1


class Socket:
    SERVER_PORT = 8001
    SERVER_HOST = '127.0.0.1'
    client: socket.socket
    lock: threading.Lock
    session_id: str

    def __init__(self) -> None:
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((Socket.SERVER_HOST, Socket.SERVER_PORT))
        self.session_id = self.client.recv(1024).decode('ascii')
        self.lock = threading.Lock()
        # self.lock.acquire()


class Player:
    team: Team
    role: Role

    def __init__(self) -> None:
        pass


class Client(Player, Socket):
    
    def __init__(self) -> None:        
        Socket.__init__(self)
        Player.__init__(self)

        print(f"session_id: {self.session_id}")

        read_thread = threading.Thread(target=self.read, args=())
        read_thread.start()

        write_thread = threading.Thread(target=self.write, args=())
        write_thread.start()


    def read(self) -> None:
        role = int(self.client.recv(BUFF_SIZE).decode('ascii'))
        self.role = Role(role)
        print(f"Player Role: {self.role}")

        while True:
            message = self.client.recv(BUFF_SIZE).decode('ascii')
            print(message)


    def write(self) -> None:
        while True:
            command = input()
            self.client.send(f"{self.session_id}::{command}".encode("ascii"))


if __name__ == "__main__":
    client = Client()
