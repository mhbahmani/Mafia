from enum import Enum, IntEnum
from hashlib import sha256

import socket, threading 
import logging
import random
import time
import json
import sys
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


TeamPlayers = {
    Team.MAFIA: [Role.MAFIA, Role.GODFATHER],
    Team.CITIZEN: [Role.CITIZEN, Role.DOCTOR, Role.DETECTIVE]
}

class Server:
    server: socket.socket
    HOST = '127.0.0.1'
    PORT = 8001
    check_winner_lock = threading.Lock()
    winner: Team = None
    end = False
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


    def handle_client(self, client: socket.socket, session_id: str):
        while not self.end:
            try:
                if session_id in self.killed_sockets: continue
                message = client.recv(BUFF_SIZE).decode("ascii")
                regex_result = re.match("(?P<session_id>[\w|=]+)::(?P<command>.+)", message)
                session_id, command = regex_result.groupdict().values()
                if command.startswith("say") and \
                    self.check_say_conditions():
                    message = re.match("say (?P<message>.+)", command).groupdict().get("message")
                    self.handle_say_command(session_id, message)
                elif command.startswith("select"):
                    player_id = int(re.match("select (?P<player_id>\d+)", command).groupdict().get("player_id"))
                    self.handle_select_command(session_id, player_id)
                elif command.startswith("offer") and \
                    self.check_offer_conditions(session_id):
                    player_id = re.match("offer (?P<player_id>\d+)", command).groupdict().get("player_id")
                    self.handle_offer_command(session_id, player_id)
                elif command.startswith("vote") and \
                    self.check_vote_conditions(session_id):
                    player_id = int(re.match("vote (?P<player_id>\d+)", command).groupdict().get("player_id"))
                    self.handle_vote_command(session_id, player_id, client)
                elif command == "next step" and \
                    self.check_next_step_conditions(session_id):
                    self.handle_next_step_command()
                elif command == "set roles" and \
                    self.check_set_roles_conditions():
                    self.handle_set_roles_command(session_id)

            except AttributeError:
                pass
            except:
                logging.error("Something bad happend")
                client.close()
                break


    def handle_offer_command(self, session_id: str, player_id: int):
        msg = f"Player {self.clients_id[session_id]} offers to kill player {player_id}"
        self.make_send_message_by_role_thread(msg, msg, [Role.STORYTELLER, Role.GODFATHER])
        logging.info(msg)


    def handle_say_command(self, session_id: str, message: str) -> None:
        msg = f"{self.clients_id[session_id]}: {message}"
        s_msg = f"{self.clients_id[session_id]} ({str(str(self.clients_role[session_id]))}): {message}"
        self.make_send_message_by_role_thread(
            message=msg,
            souls_message=s_msg,
            exclude_roles=[self.clients_role[session_id]])
        logging.info(msg)

    
    def handle_select_command(self, session_id: str, player_id: int) -> None:
        if self.clients_role[session_id] == Role.DOCTOR:
            logging.info(f"Doctor wants to save {player_id}")
            self.selected[Role.DOCTOR] = True
            self.saved_player = player_id
            logging.info(f"Saved player save. Player id: {player_id}")
        elif self.clients_role[session_id] == Role.DETECTIVE:
            if self.selected[Role.DETECTIVE]: return
            self.selected[Role.DETECTIVE] = True
            logging.info(f"Player {self.clients_id[session_id]} (Detective) asks player {player_id} team")
            target_team = self.get_team(player_id=player_id)
            s_msg = f"Player {self.clients_id[session_id]} (Detective) asks player {player_id} team\nInquiry Result: Player {player_id} role is {str(target_team)}"
            self.make_send_message_by_role_thread(
                message=f"Inquiry Result: Player {player_id} role is {str(target_team)}",
                souls_message=s_msg,
                recipients_role=[Role.STORYTELLER, Role.DETECTIVE]
            )
            logging.info(f"Inquiry result sent: {str(target_team)}")
        elif self.clients_role[session_id] == Role.GODFATHER:
            self.selected[Role.GODFATHER] = True
            logging.info(f"Player {self.clients_id[session_id]} (Godfather) wants to kill player {player_id}")
            self.killed_player = player_id

    
    def handle_vote_command(self, session_id: str, player_id: int, client: socket.socket) -> None:
        if player_id in self.killed_ids: 
            logging.info(f"Voted player by {self.clients_id[session_id]} is dead already")
            client.send(f"Player {player_id} is dead idiot :/")
            return
        self.votes[player_id] += 1
        self.voted[session_id] = True
        msg = f"Player {self.clients_id[session_id]} voted to {player_id} --> {json.dumps(self.votes)}"
        self.make_send_message_by_role_thread(msg, msg)
        logging.info(f"Player {self.clients_id[session_id]} voted to {player_id}")


    def handle_set_roles_command(self, session_id: str) -> None:
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
        from collections import OrderedDict
        self.votes = OrderedDict(sorted(self.votes.items()))

                
    def handle_next_step_command(self):
        threading.Thread(target=self.next_phase, args=()).start()


    def server_listener(self):
        while not self.end:
            try:
                if self.end: break
                client, address = self.server.accept()
                session_id = sha256(bytes(f"client{address}", "utf-8")).hexdigest()[-20:]
                logging.info(f"New player accepted with id {session_id}")
                client.send(session_id.encode("ascii"))
                self.clients_socket[session_id] = client
                thread = threading.Thread(target=self.handle_client, args=(client, session_id,))
                thread.start()
            except:
                if self.end: break
                pass

    def handle_votes(self):
        selected_players = [k for k, v in self.votes.items() if v == max(self.votes.values())]
        if len(selected_players) > 1: return
        if len(selected_players) == 1:
            msg = f"Player {selected_players[0]} got killed"
            s_msg = f"Player {selected_players[0]} ({str(self.clients_role.get(self.ids[selected_players[0]], 'Unknown'))}) got killed"
            logging.info(msg)
            self.kill_player(
                killed_session_id=self.ids[selected_players[0]],
                killed_player_id=selected_players[0],
                message=msg,
                souls_message=s_msg)


    def send_message_by_role(self, message: str, recipients_role: list):
        for role in recipients_role:
            self.clients_socket.get(self.roles[role], self.killed_sockets.get(self.roles[role])).send(message.encode("ascii"))


    def send_message_to_souls(self, message: str):
        for soul in self.killed_sockets.values():
            soul.send(message.encode("ascii"))


    def send_to_all(self, message: str) -> None:
        for player in self.clients_socket:
            self.clients_socket[player].send(message.encode("ascii"))


    def next_phase(self) -> None:
        last_phase = self.phase
        self.phase = Phase((self.phase + 1) % 3)

        if last_phase == Phase.VOTE:
            logging.info("Voting ended")
            handle_votes_thread = threading.Thread(target=self.handle_votes, args=())
            handle_votes_thread.start()
            handle_votes_thread.join()
            
            if self.winner:
                self.end_game()
                return
        elif last_phase == Phase.NIGHT:
            # Handle doctor save himeslef
            if self.saved_player == self.clients_id.get(self.roles[Role.DOCTOR], 0):
                if self.doctor_saved_himself: self.saved_player = 0
                else: self.doctor_saved_himself = True

            # Handle doctor saved and assassinated player
            if self.killed_player:
                if self.saved_player == self.killed_player:
                    logging.info(f"Doctor saved assassinated player (Player {self.saved_player})")
                    msg = "No one died last night"
                    self.make_send_message_by_role_thread(msg, msg)
                else:
                    logging.info(f"The mobs killed player {self.killed_player}")
                    self.kill_player(
                        killed_session_id=self.ids[self.killed_player],
                        killed_player_id=self.killed_player,
                        message=f"Player {self.killed_player} from {str(self.get_team(self.killed_player))} team got killed last night")

        logging.info(f"Going to Next Phase: {str(self.phase)}")

        msg = ""
        if self.phase == Phase.NIGHT: msg = "* Sleeeeeeep! *"
        elif self.phase == Phase.DAY: msg = "* Time to wake! *"
        elif self.phase == Phase.VOTE: msg = "* Mizan Ray Mellat Ast! *"
        msg = f"Going to next phase: {str(self.phase)}\n{msg}"
        self.make_send_message_by_role_thread(msg, msg)

        if self.winner:
            self.end_game()
            return
                                
        ## clear votes
        for player_id in self.votes:
            self.votes[player_id] = 0
        self.voted = {}
        # clear selected
        for role in self.selected:
            self.selected[role] = False
        self.saved_player = 0
        self.killed_player = 0


    def check_winner(self):
        # if self.check_winner_lock.locked():
        #     pass
        teams_players_number = self.count_each_team_players()
        if teams_players_number[Team.MAFIA] == teams_players_number[Team.CITIZEN]:
            self.winner = Team.MAFIA
        elif teams_players_number[Team.MAFIA] == 0: self.winner = Team.CITIZEN
        if not self.winner: return
        # self.check_winner_lock.acquire()
    
        logging.info(f"Team {str(self.winner)} won")


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


    def kill_player(self, killed_session_id: str, killed_player_id: int, message: str, souls_message: str=None) -> None:
        if not souls_message: souls_message = message
        self.killed_sockets[killed_session_id] = self.clients_socket[killed_session_id]
        self.killed_roles.append(self.clients_role[killed_session_id])
        self.killed_ids[killed_player_id] = killed_session_id
        self.votes.pop(killed_player_id)
        self.clients_socket.pop(killed_session_id).send("*** YOU GOT KILLED :(\nSit tight and watch your teamates work\n-----".encode("ascii"))
        self.clients_role.pop(killed_session_id)
        self.clients_id.pop(killed_session_id)
        self.make_send_message_by_role_thread(message=message, souls_message=souls_message)
        self.make_check_winner_thread()



    def get_team(self, role: Role=None, player_id: int= None) -> Team:
        if player_id in self.killed_ids: return Team.DEAD
        if player_id and not role: role = self.clients_role[self.ids[player_id]]
        return Team.MAFIA if role == Role.MAFIA else Team.CITIZEN


    def count_each_team_players(self) -> dict:
        teams = {
            Team.MAFIA: 0,
            Team.CITIZEN: 0
        }
        for player_role in self.clients_role.values():
            if player_role == Role.STORYTELLER: continue
            elif player_role in [Role.MAFIA, Role.GODFATHER]: teams[Team.MAFIA] += 1
            else: teams[Team.CITIZEN] += 1
        return teams

    
    def end_game(self) -> None:
        self.make_send_message_by_role_thread(message="You Won!", team=self.winner)
        self.make_send_message_by_role_thread(message="You Lost!", team=Team(-self.winner))
        self.make_send_message_by_role_thread(message="End", recipients_role=[Role.STORYTELLER])

        time.sleep(1)
        self.server.close()
        self.end = True


    def make_send_message_by_role_thread(self, message: str, souls_message: str = None, recipients_role: list = list(Role), exclude_roles: list = [], team: Team = None):
        """
            If recipients_role not set, send to all 
        """
        if team:
            threading.Thread(
                target=self.send_message_by_role,
                args=(
                    message,
                    TeamPlayers[team]
                )
            ).start()
        else:
            threading.Thread(
                target=self.send_message_by_role,
                args=(
                    message,
                    list(set(recipients_role) - set(exclude_roles) - set(self.killed_roles)),
                )
            ).start()
            if souls_message:
                threading.Thread(
                    target=self.send_message_to_souls,
                    args=(souls_message, )
                ).start()


    def make_check_winner_thread(self):
        check_winner_thrad = threading.Thread(
            target=self.check_winner,
            args=()
        )
        check_winner_thrad.start()
        check_winner_thrad.join()


if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level={
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            }['INFO'])
    server = Server()
    server.server_listener()
    server.server.close()
    sys.exit()
