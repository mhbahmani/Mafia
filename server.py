from enum import IntEnum
from hashlib import sha256

import socket, threading
import logging
import json
import re


BUFF_SIZE = 1024


class Phase(IntEnum):
    NIGHT = 0
    DAY = 1
    VOTE = 2


class Role(IntEnum):
    # CITIZEN = 0
    # DOCTOR = 1
    # DETECTIVE = 2
    MAFIA = 3
    GODFATHER = 4
    STORYTELLER = 5


class Team(IntEnum):
    MAFIA = 1
    STORYTELLER = 0
    CITIZEN = -1


class Server:
    server: socket.socket
    HOST = '127.0.0.1'
    PORT = 8000
    phase: Phase = Phase.DAY
    # Key: Session_id    Value: Socket
    clients_socket: dict
    # Key: Session_id    Value: Role
    clients_role: dict
    # Key: Session_id    Value: Id
    clients_id: dict
    # Key: Id            Valeu: Votes
    votes: dict
    # Key: Session_id    Valeu: Voted
    voted: dict
    # Key: Role          Value: Session_id
    roles: dict


    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((Server.HOST, Server.PORT))
        self.server.listen(1)
        logging.info(f"Server is listening on {Server.HOST}:{Server.PORT}")

        self.clients_socket = {}
        self.clients_role = {}
        self.clients_id = {}
        self.roles = {}
        self.votes = {}
        self.voted = {}

        server_thread = threading.Thread(target=self.server_listener, args=())
        server_thread.start()


    def handle_client(self, client: socket.socket, session_id: str):
        while True:
            try:
                message = client.recv(BUFF_SIZE).decode("ascii")
                regex_result = re.match("(?P<session_id>[\w|=]+)::(?P<command>.+)", message)
                session_id, command = regex_result.groupdict().values()
                if command.startswith("say") and \
                    self.check_say_conditions():
                    message = re.match("say (?P<message>.+)", command).groupdict().get("message")
                    for session in self.clients_socket:
                        if session == session_id: continue
                        self.clients_socket[session].send(f"{self.clients_id[session_id]}: {message}".encode("ascii"))
                elif command.startswith("select"):
                    player_id = re.match("select (?P<player_id>\d+)", command).groupdict().values()
                elif command.startswith("offer") and \
                    self.check_offer_conditions(session_id):
                    player_id = re.match("offer (?P<player_id>\d+)", command).groupdict().get("player_id")
                    msg = f"Player {self.clients_id[session_id]} offers to kill player {player_id}"
                    self.make_send_message_by_role_thread(msg, [Role.STORYTELLER, Role.GODFATHER])
                    logging.info(msg)
                elif command.startswith("vote") and \
                    self.check_vote_conditions(session_id):
                    player_id = int(re.match("vote (?P<player_id>\d+)", command).groupdict().get("player_id"))
                    self.votes[player_id] += 1
                    self.voted[session_id] = True
                    msg = f"Player {self.clients_id[session_id]} voted to {player_id}"
                    self.make_send_message_by_role_thread(msg)
                    logging.info(f"Player {self.clients_id[session_id]} voted to {player_id}")
                elif command == "next step" and \
                    self.check_next_step_conditions(session_id):
                    threading.Thread(target=self.next_phase, args=()).start()
                    logging.info(f"Going to Next Phase: {str(self.phase)}")
                elif command == "set roles" and \
                    self.check_set_roles_conditions():
                    self.roles[Role.STORYTELLER] = session_id
                    self.clients_role[session_id] = Role.STORYTELLER
                    self.clients_socket[session_id].send(str(int(Role.STORYTELLER)).encode("ascii"))
                    for role in Role:
                        if role == Role.STORYTELLER: continue
                        for session in self.clients_socket:
                            if self.clients_role.get(session) != None: continue
                            self.clients_role[session] = role
                            self.roles[role] = session
                            self.clients_socket[session].send(str(int(role)).encode("ascii"))
                            break
                        
                        
            except ValueError:
                logging.error("Something bad happend")
                # client.close()
                # self.clients_socket.pop(session_id)
                # self.clients_role.pop(session_id)
                # self.clients_id.pop(session_id)
                break


    def server_listener(self):
        while True:
            client, address = self.server.accept()
            session_id = sha256(bytes(f"client{address}", "utf-8")).hexdigest()[-20:]
            logging.info(f"New player accepted with id {session_id}")
            client.send(session_id.encode("ascii"))
            self.clients_socket[session_id] = client
            self.clients_id[session_id] = len(self.clients_socket)
            self.votes[self.clients_id[session_id]] = 0
            self.voted[session_id] = True
            thread = threading.Thread(target=self.handle_client, args=(client, session_id,))
            thread.start()


    def make_send_message_by_role_thread(self, message: str, recipients_role: list = list(Role)):
        """
            If recipients_role not set, send to all 
        """
        threading.Thread(target=self.send_message_by_role, args=(message, recipients_role,)).start()


    def send_message_by_role(self, message: str, recipients_role: list):
        for role in recipients_role:
            self.clients_socket[self.roles[role]].send(message.encode("ascii"))


    def send_to_all(self, message: str) -> None:
        for player in self.clients_socket:
            self.clients_socket[player].send(message.encode("ascii"))


    def next_phase(self) -> None:
        self.phase = Phase((self.phase + 1) % 3)
        self.make_send_message_by_role_thread(message=f"Going to next phase: {str(self.phase)}")
        self.clear_votes()


    def clear_votes(self) -> None:
        for player_id in self.votes:
            self.votes[player_id] = 0
        for session_id in self.voted:
            self.voted[session_id] = False


    def check_vote_conditions(self, session_id: str) -> bool:
        return self.phase == Phase.VOTE and \
            not self.voted[session_id] and \
            self.clients_role[session_id] != Role.STORYTELLER

    def check_set_roles_conditions(self) -> bool:
        return self.phase == Phase.DAY and \
            not self.roles.get(Role.STORYTELLER) and \
            len(self.clients_socket) == 3

    def check_next_step_conditions(self, session_id: str) -> bool:
        return self.clients_role.get(session_id) == Role.STORYTELLER

    def check_say_conditions(self) -> bool:
        return self.phase == Phase.DAY

    def check_offer_conditions(self, session_id: str) -> bool:
        return self.phase == Phase.NIGHT and \
            self.clients_role.get(session_id) == Role.MAFIA


if __name__ == "__main__":
    logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level={
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG,
        'ERROR': logging.ERROR,
        }['INFO'])
    server = Server()
