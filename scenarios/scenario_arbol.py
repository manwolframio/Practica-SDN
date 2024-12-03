!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
from time import sleep

class SingleSwitchTopo(Topo):

	def build(self):
		hosts=[]
		swicthes=[]
		for i in range (0,10):
			sw = self.addSwitch(name = 's{}'.format(i))
			h = self.addHost(name = 'h{}'.format(i), ip = "10.0.0.{}".format(i+1),mac="00:00:00:{}".format(i+1))
			self.addLink(sw, h)
			if(i > 0):
				self.addLink(sw, swicthes[0])
			hosts.append(h)
			swicthes.append(sw)




if __name__ == '__main__':
	setLogLevel('info')
	topo = SingleSwitchTopo()
	c1 = RemoteController('c1', ip='172.0.0.1') # Se va a conectar a la IP del host con ryu
	net = Mininet(topo=topo, controller=c1)
	net.start()
	sleep(5)
	CLI(net)
	net.stop()

