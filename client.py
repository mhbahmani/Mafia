from enum import IntEnum
import socket, threading
import sys


BUFF_SIZE = 1024


class Phase(IntEnum):
    NIGHT = 0
    DAY = 1
    VOTE = 2


class Role(IntEnum):
    CITIZEN = 1
    DOCTOR = 2
    DETECTIVE = 3
    MAFIA = 4
    GODFATHER = 5
    STORYTELLER = 6

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
    session_id: str

    def __init__(self) -> None:
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((Socket.SERVER_HOST, Socket.SERVER_PORT))
        self.session_id = self.client.recv(1024).decode('ascii')


class Player:
    team: Team
    role: Role
    end = False

    def __init__(self) -> None:
        pass


class Client(Player, Socket):
    
    def __init__(self) -> None:        
        Socket.__init__(self)
        Player.__init__(self)

        print(f"session_id: {self.session_id}")

        write_thread = threading.Thread(target=self.write, args=())
        write_thread.start()

        read_thread = threading.Thread(target=self.read, args=())
        read_thread.start()
        read_thread.join()


    def read(self) -> None:
        role = int(self.client.recv(BUFF_SIZE).decode('ascii'))
        self.role = Role(role)
        print(f"Player Role: {self.role}")

        while not self.end:
            message = self.client.recv(BUFF_SIZE).decode('ascii')
            print(message)
            if message == "You Won!" or message == "You Lost!" or message == "End":
                self.end = True
                print("Press enter to end")


    def write(self) -> None:
        while not self.end:
            try:
                command = input()
                self.client.send(f"{self.session_id}::{command}".encode("ascii"))
            except:
                pass


if __name__ == "__main__":
    client = Client()
    client.client.close()
    sys.exit()
