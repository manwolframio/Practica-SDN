"""
Autor: Nicolás Manso
Departamento: Automática
Laboratorio: Le34
Universidad de Alcalá (UAH)

Descripción:
Este script implementa una aplicación Ryu para gestionar un firewall basado en switches OpenFlow (versión 1.3). 
Esta aplicación es carga un conjunto de reglas de firewall desde un archivo externo 
y aplicarlas dinámicamente a los switches en la red.

Características principales:
- Carga de reglas desde un archivo `firewall_rules.txt` con soporte para comodines y comentarios.
- Filtrado de tráfico basado en las direcciones MAC de origen/destino y switches específicos.
- Creación de reglas dinámicas en función de las políticas definidas en las reglas de firewall.
- Denegación por defecto para tráfico no definido explícitamente en las reglas.

Notas:
- Las reglas deben estar definidas en el archivo de entrada con el siguiente formato (separado por tabulaciones):
  `enabled	mac_src	mac_dst	policy	switch`
- El encabezado del archivo debe coincidir con el formato esperado; de lo contrario, se generará un error.

Requisitos:
- Framework Ryu.
- Archivo de reglas `firewall_rules.txt` ubicado en el mismo directorio que el script.

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import re
import pdb


class FirewallSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(FirewallSwitch, self).__init__(*args, **kwargs)
		self.firewall_rules = []
		self.load_firewall_rules('firewall_rules.txt')  # Cargar las reglas desde el archivo
		self.datapaths = {}

	def load_firewall_rules(self, file_path):
		"""
		Carga las reglas del firewall desde un archivo.
		Formato: enabled, mac_src, mac_dst, policy, switch
		"""
		try:
			with open(file_path, 'r') as f:
				lines = f.readlines()
				if not lines:
					self.logger.error("El archivo de reglas está vacío.")
					return
				
				header = lines[0].strip().split('\t')
				if header != ['enabled', 'mac_src', 'mac_dst', 'policy', 'switch']:
					self.logger.error("El encabezado del archivo de reglas es inválido.")
					return

				for line in lines[1:]:  # Ignorar la primera línea (encabezado)
					line = line.strip()
					if not line or line.startswith("#"):  # Ignorar líneas vacías o comentarios
						continue
					fields = line.split('\t')
					if len(fields) != 5:
						self.logger.error("Regla inválida: %s", line)
						continue
					enabled, mac_src, mac_dst, policy, switch = [field.strip() for field in fields]
					self.firewall_rules.append({
						'enabled': enabled.lower() == 'enable',
						'mac_src': mac_src,
						'mac_dst': mac_dst,
						'policy': policy.lower() == 'allow',
						'switches': switch.split(',')
					})
			self.logger.info("Reglas del firewall cargadas: %d reglas", len(self.firewall_rules))
		except FileNotFoundError:
			self.logger.error("Archivo de reglas no encontrado: %s", file_path)

	def match_mac(self, rule_mac, pkt_mac):
		"""
		Compara una MAC con una regla que puede contener comodines (*).
		"""
		rule_regex = '^' + rule_mac.replace('*', '.*') + '$'
		return re.match(rule_regex, pkt_mac, re.IGNORECASE) is not None

	def match_switch(self, rule_switches, switch_id):
		"""
		Verifica si un switch está incluido en una lista de switches o si aplica para todos (*).
		"""
		return '*' in rule_switches or f's{switch_id}' in rule_switches

	def is_packet_allowed(self, src_mac, dst_mac, switch_id):
		"""
		Evalúa si un paquete está permitido según las reglas del firewall.
		"""
		for rule in self.firewall_rules:
			if not rule['enabled']:
				continue
			if (self.match_switch(rule['switches'], switch_id) and
					self.match_mac(rule['mac_src'], src_mac) and
					self.match_mac(rule['mac_dst'], dst_mac)):
				return rule['policy']  # Devuelve True (allow) o False (disallow)
		return False  # Por defecto denegar si no hay coincidencias

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		self.datapaths[datapath.id] = datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Instalar una regla table-miss
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		self.logger.info("Switch conectado: %s", datapath.id)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		"""
		Añade un flujo a un switch.
		"""
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		switch_id = datapath.id  # Identificador del switch
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# Ignorar paquetes LLDP
			return

		src_mac = eth.src
		dst_mac = eth.dst

		# Verificar si el paquete está permitido o no
		if self.is_packet_allowed(src_mac, dst_mac, switch_id):
			# self.logger.info("Paquete permitido: %s -> %s en switch s%s", src_mac, dst_mac, switch_id)

			# Crear una regla para permitir tráfico futuro entre src y dst
			match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
			actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
			self.add_flow(datapath, 1, match, actions)

			# Enviar el paquete actual
			out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
									  in_port=in_port, actions=actions, data=msg.data)
			datapath.send_msg(out)
		else:
			self.logger.info("Paquete bloqueado: %s -> %s en switch s%s", src_mac, dst_mac, switch_id)

			# Crear una regla para bloquear tráfico futuro (política nula)
			match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
			actions = []  # Sin acciones = Bloqueo
			self.add_flow(datapath, 1, match, actions)
