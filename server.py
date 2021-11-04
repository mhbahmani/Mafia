from enum import IntEnum
from hashlib import sha256

import socket, threading
import logging
import random
import json
import re


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


class Team(IntEnum):
    MAFIA = 1
    DEAD = 0
    CITIZEN = -1


class Server:
    server: socket.socket
    HOST = '127.0.0.1'
    PORT = 8000
    phase: Phase = Phase.DAY
    saved_player = 0
    killed_player = 0
    doctor_saved_himself = False
    # Key: Role          Value: Selected or not
    selected = {
            Role.DOCTOR: False,
            Role.DETECTIVE: False,
            Role.GODFATHER: False
        }
    # Key Session_id     Value: Socket
    killed_sockets = {}
    killed_roles = []
    # Key: Id            Value: Session_id
    killed_ids = {}
    # Key: Session_id    Value: Socket
    clients_socket = {}
    # Key: Session_id    Value: Role
    clients_role = {}
    # Key: Session_id    Value: Id
    clients_id = {}
    # Key: Id            Valeu: Votes
    votes = {}
    # Key: Session_id    Valeu: Voted
    voted = {}
    # Key: Role          Value: Session_id
    roles = {}
    # Key: Id            Value: Session_id
    ids = {}


    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((Server.HOST, Server.PORT))
        self.server.listen(1)
        logging.info(f"Server is listening on {Server.HOST}:{Server.PORT}")

        server_thread = threading.Thread(target=self.server_listener, args=())
        server_thread.start()


    def handle_client(self, client: socket.socket, session_id: str):
        while True:
            try:
                message = client.recv(BUFF_SIZE).decode("ascii")
                regex_result = re.match("(?P<session_id>[\w|=]+)::(?P<command>.+)", message)
                session_id, command = regex_result.groupdict().values()
                if session_id in self.killed_sockets:
                    continue
                if command.startswith("say") and \
                    self.check_say_conditions():
                    message = re.match("say (?P<message>.+)", command).groupdict().get("message")
                    msg = f"{self.clients_id[session_id]}: {message}"
                    self.make_send_message_by_role_thread(
                        message=f"{self.clients_id[session_id]}: {message}",
                        exclude_roles=[self.clients_role[session_id]])
                    logging.info(msg)
                elif command.startswith("select"):
                    player_id = int(re.match("select (?P<player_id>\d+)", command).groupdict().get("player_id"))
                    if self.clients_role[session_id] == Role.DOCTOR:
                        logging.info(f"Doctor wants to save {player_id}")
                        # if self.selected[Role.DOCTOR]: continue
                        self.selected[Role.DOCTOR] = True
                        self.saved_player = player_id
                        logging.info(f"Saved player save. Player id: {player_id}")
                    elif self.clients_role[session_id] == Role.DETECTIVE:
                        if self.selected[Role.DETECTIVE]: continue
                        self.selected[Role.DETECTIVE] = True
                        logging.info(f"Player {self.clients_id[session_id]} (Detective) asks player {player_id} team")
                        target_team = self.get_team(player_id=player_id)
                        self.make_send_message_by_role_thread(
                            message=f"Inquiry Result: Player {player_id} role is {str(target_team)}",
                            recipients_role=[Role.STORYTELLER, Role.DETECTIVE]
                        )
                        logging.info(f"Inquiry result sent: {str(target_team)}")
                    elif self.clients_role[session_id] == Role.GODFATHER:
                        # if self.selected[Role.GODFATHER]: continue
                        self.selected[Role.GODFATHER] = True
                        logging.info(f"Player {self.clients_id[session_id]} (Godfather) wants to kill player {player_id}")
                        self.killed_player = player_id
                elif command.startswith("offer") and \
                    self.check_offer_conditions(session_id):
                    player_id = re.match("offer (?P<player_id>\d+)", command).groupdict().get("player_id")
                    msg = f"Player {self.clients_id[session_id]} offers to kill player {player_id}"
                    self.make_send_message_by_role_thread(msg, [Role.STORYTELLER, Role.GODFATHER])
                    logging.info(msg)
                elif command.startswith("vote") and \
                    self.check_vote_conditions(session_id):
                    player_id = int(re.match("vote (?P<player_id>\d+)", command).groupdict().get("player_id"))
                    logging.info(f"Player {self.clients_id[session_id]} vote to {player_id}")
                    if player_id in self.killed_ids: 
                        logging.info(f"Voted player by {self.clients_id[session_id]} is dead already")
                        client.send(f"Player {player_id} is dead idiot :/")
                        continue
                    self.votes[player_id] += 1
                    self.voted[session_id] = True
                    msg = f"Player {self.clients_id[session_id]} voted to {player_id}"
                    self.make_send_message_by_role_thread(f"{msg} --> {json.dumps(self.votes)}")
                    logging.info(f"Player {self.clients_id[session_id]} voted to {player_id}")
                    if len(self.voted) == len(self.clients_socket) - 1:
                        logging.info("Voting ended")
                        threading.Thread(target=self.handle_votes, args=()).start()
                elif command == "next step" and \
                    self.check_next_step_conditions(session_id):
                    threading.Thread(target=self.next_phase, args=()).start()
                elif command == "set roles" and \
                    self.check_set_roles_conditions():
                    self.roles[Role.STORYTELLER] = session_id
                    self.clients_role[session_id] = Role.STORYTELLER
                    self.clients_socket[session_id].send(str(int(Role.STORYTELLER)).encode("ascii"))
                    self.clients_id[session_id] = len(Role)
                    self.ids[self.clients_id[session_id]] = session_id

                    ids = list(range(1, 6))
                    random.shuffle(ids)
                    i2 = 0
                    for role in Role:
                        if role == Role.STORYTELLER: continue
                        for i, session in enumerate(self.clients_socket):
                            if self.clients_role.get(session) != None: i2 = 1; continue
                            self.clients_role[session] = role
                            self.clients_id[session] = ids[i - i2]
                            self.ids[ids[i - i2]] = session
                            self.votes[ids[i - i2]] = 0
                            self.roles[role] = session
                            self.clients_socket[session].send(str(int(role)).encode("ascii"))
                            break
                        
                        
            except ValueError:
                logging.error("Something bad happend")
                client.close()
                self.clients_socket.pop(session_id)
                self.clients_role.pop(session_id)
                self.clients_id.pop(session_id)
                break


    def server_listener(self):
        while True:
            client, address = self.server.accept()
            session_id = sha256(bytes(f"client{address}", "utf-8")).hexdigest()[-20:]
            logging.info(f"New player accepted with id {session_id}")
            client.send(session_id.encode("ascii"))
            self.clients_socket[session_id] = client
            thread = threading.Thread(target=self.handle_client, args=(client, session_id,))
            thread.start()


    def handle_votes(self):
        selected_players = [k for k, v in self.votes.items() if v == max(self.votes.values())]
        if len(selected_players) > 1: return
        if len(selected_players) == 1:
            msg = f"Player {selected_players[0]} killed"
            logging.info(msg)
            self.kill_player(
                killed_session_id=self.ids[selected_players[0]],
                killed_player_id=selected_players[0],
                message=msg)


    def make_send_message_by_role_thread(self, message: str, recipients_role: list = list(Role), exclude_roles: list = []):
        """
            If recipients_role not set, send to all 
        """
        threading.Thread(
            target=self.send_message_by_role,
            args=(
                message,
                list(set(recipients_role) - set(exclude_roles) - set(self.killed_roles)),
            )
        ).start()


    def send_message_by_role(self, message: str, recipients_role: list):
        for role in recipients_role:
            self.clients_socket[self.roles[role]].send(message.encode("ascii"))


    def send_to_all(self, message: str) -> None:
        for player in self.clients_socket:
            self.clients_socket[player].send(message.encode("ascii"))


    def next_phase(self) -> None:
        last_phase = self.phase
        self.phase = Phase((self.phase + 1) % 3)
        msg = ""
        if self.phase == Phase.NIGHT: msg = "* Sleeeeeeep! *"
        elif self.phase == Phase.DAY: msg = "* Time to wake! *"
        elif self.phase == Phase.VOTE: msg = "* Mizan Ray Mellat Ast! *"
        self.make_send_message_by_role_thread(message=f"Going to next phase: {str(self.phase)}\n{msg}")
        logging.info(f"Going to Next Phase: {str(self.phase)}")
        if last_phase == Phase.NIGHT:
            # Handle doctor save himeslef
            if self.saved_player == self.clients_id.get(self.roles[Role.DOCTOR], 0):
                if self.doctor_saved_himself: self.saved_player = 0
                else: self.doctor_saved_himself = True

            # Handle doctor saved and assassinated player
            if self.saved_player == self.killed_player:
                logging.info(f"Doctor saved assassinated player (Player {self.saved_player})")
                self.make_send_message_by_role_thread("No one died last night")
            else:
                logging.info(f"The mobs killed player {self.killed_player}")
                self.kill_player(
                    killed_session_id=self.ids[self.killed_player],
                    killed_player_id=self.killed_player,
                    message=f"Player {self.killed_player} got killed last night")

        ## clear votes
        for player_id in self.votes:
            self.votes[player_id] = 0
        self.voted = {}
        # clear selected
        for role in self.selected:
            self.selected[role] = False
        self.saved_player = 0
        self.killed_player = 0



    def check_vote_conditions(self, session_id: str) -> bool:
        return self.phase == Phase.VOTE and \
            not self.voted.get(session_id, False) and \
            self.clients_role[session_id] != Role.STORYTELLER

    def check_set_roles_conditions(self) -> bool:
        return self.phase == Phase.DAY and \
            not self.roles.get(Role.STORYTELLER) and \
            len(self.clients_socket) == len(Role)

    def check_next_step_conditions(self, session_id: str) -> bool:
        return self.clients_role.get(session_id) == Role.STORYTELLER

    def check_say_conditions(self) -> bool:
        return self.phase == Phase.DAY

    def check_offer_conditions(self, session_id: str) -> bool:
        return self.phase == Phase.NIGHT and \
            self.clients_role.get(session_id) == Role.MAFIA


    def kill_player(self, killed_session_id: str, killed_player_id: int, message: str) -> None:
        self.make_send_message_by_role_thread(message=message)
        self.killed_sockets[killed_session_id] = self.clients_socket[killed_session_id]
        self.killed_roles.append(self.clients_role[killed_session_id])
        self.killed_ids[killed_player_id] = killed_session_id
        self.clients_socket.pop(killed_session_id)
        self.clients_role.pop(killed_session_id)
        self.clients_id.pop(killed_session_id)


    def get_team(self, role: Role=None, player_id: int= None) -> Team:
        if player_id in self.killed_ids: return Team.DEAD
        if player_id and not role: role = self.clients_role[self.ids[player_id]]
        return Team.MAFIA if role == Role.MAFIA else Team.CITIZEN


if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level={
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            }['INFO'])
    server = Server()
