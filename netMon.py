from Tkinter import *
from struct import *
import threading
import socket
import copy
import time

class NetworkMonitor:
   def __init__(self):
      self.inbound = {}
      self.outbound = {}
      self.createRoot()
      self.createIpWindow()
      self.root.mainloop()      

   def createRoot(self):
      self.root = Tk()
      self.root.resizable(width=FALSE,height=FALSE)
      self.root.title("Network Monitor")

   def createIpWindow(self):
      self.ipFrame = Frame(self.root,bd=5)
      self.ipLabel = Label(self.ipFrame,text="IP Address:")
      self.ipEntry = Entry(self.ipFrame)
      self.ipButton = Button(self.ipFrame,text="Next",command=self.verifyIp)
      self.ipFrame.pack()
      self.ipLabel.grid(row=1,column=1)
      self.ipEntry.grid(row=1,column=2,padx=5)
      self.ipButton.grid(row=1,column=3)

   def verifyIp(self):
      try:
         self.errorLabel
      except:
         self.createErrorLabel()
      IP = self.ipEntry.get()
      if IP in self.getIps():
         sock = self.getSocket(IP)
         if sock == None:
            self.errorLabel.config(text="Forbidden Access")
         else:
            self.prepareMonitor(IP,sock)
      else:
         self.errorLabel.config(text="Bad Address")

   def createErrorLabel(self):
      self.errorLabel = Label(self.ipFrame)
      self.errorLabel.grid(row=2,column=2)

   def getIps(self):
      addressInfo = socket.getaddrinfo(socket.gethostname(),None)
      Ips = []
      for info in addressInfo:
         Ips.append(info[4][0])
      return Ips

   def getSocket(self,IP):
      try:
         sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
         sock.bind((IP,0))
         sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
         sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
         return sock
      except:
         return None

   def prepareMonitor(self,IP,sock):
      self.destroyIpWindow()
      self.createMonitorWindow()
      threading.Thread(target=self.updateMonitorWindow).start()
      threading.Thread(target=self.monitor, args=(IP,sock,)).start()
      
   def destroyIpWindow(self):
      self.ipFrame.pack_forget()
      self.ipFrame.destroy()

   def createMonitorWindow(self):
      monitorFrameInbound = Frame(self.root,bd=5)
      monitorFrameInboundLabel = Frame(monitorFrameInbound)
      monitorFrameInboundText = Frame(monitorFrameInbound)
      monitorFrameOutbound = Frame(self.root,bd=5)
      monitorFrameOutboundLabel = Frame(monitorFrameInbound)
      monitorFrameOutboundText = Frame(monitorFrameInbound)

      monitorScrollbarXInbound = Scrollbar(monitorFrameInboundText, orient=HORIZONTAL)
      monitorScrollbarYInbound = Scrollbar(monitorFrameInboundText)
      monitorLabelInbound = Label(monitorFrameInboundLabel,text="INBOUND")
      self.monitorTextInbound = Text(monitorFrameInboundText,width=100,height=10,wrap=NONE,xscrollcommand=monitorScrollbarXInbound.set,yscrollcommand=monitorScrollbarYInbound.set,state=DISABLED)

      monitorScrollbarXOutbound = Scrollbar(monitorFrameOutboundText, orient=HORIZONTAL)
      monitorScrollbarYOutbound = Scrollbar(monitorFrameOutboundText)
      monitorLabelOutbound = Label(monitorFrameOutboundLabel,text="OUTBOUND")
      self.monitorTextOutbound = Text(monitorFrameOutboundText,width=100,height=10,wrap=NONE,xscrollcommand=monitorScrollbarXOutbound.set,yscrollcommand=monitorScrollbarYOutbound.set,state=DISABLED)

      monitorFrameInbound.pack()
      monitorFrameInboundLabel.pack()
      monitorFrameInboundText.pack()
      monitorFrameOutbound.pack()
      monitorFrameOutboundLabel.pack()
      monitorFrameOutboundText.pack()
      monitorScrollbarXInbound.pack(side=BOTTOM,fill=X)
      monitorScrollbarYInbound.pack(side=RIGHT,fill=Y)
      monitorLabelInbound.pack()
      self.monitorTextInbound.pack()
      monitorScrollbarXOutbound.pack(side=BOTTOM,fill=X)
      monitorScrollbarYOutbound.pack(side=RIGHT,fill=Y)
      monitorLabelOutbound.pack()
      self.monitorTextOutbound.pack()

      monitorScrollbarXInbound.config(command=self.monitorTextInbound.xview)
      monitorScrollbarYInbound.config(command=self.monitorTextInbound.yview)
      monitorScrollbarXOutbound.config(command=self.monitorTextOutbound.xview)
      monitorScrollbarYOutbound.config(command=self.monitorTextOutbound.yview)

      monitorButton = Button(self.root,text="Reset",command=self.resetMonitor)
      monitorButton.pack(pady=5)

   def resetMonitor(self):
      self.inbound = {}
      self.outbound = {}

   def updateMonitorWindow(self):
      oldInbound = {}
      oldOutbound = {}
      while True:
         currentInbound = copy.deepcopy(self.inbound)
         currentOutbound = copy.deepcopy(self.outbound)
         
         inboundData = self.parseData(currentInbound)
         outboundData = self.parseData(currentOutbound)
         
         inboundChanges = self.getChanges(oldInbound,currentInbound)
         outboundChanges = self.getChanges(oldOutbound,currentOutbound)
         
         inboundChangeLocations = self.getChangeLocations(inboundData,inboundChanges)
         outboundChangeLocations = self.getChangeLocations(outboundData,outboundChanges)
         
         self.monitorTextInbound.config(state=NORMAL)
         self.monitorTextOutbound.config(state=NORMAL)
         self.monitorTextInbound.delete(1.0,END)
         self.monitorTextOutbound.delete(1.0,END)
         self.monitorTextInbound.insert(END,inboundData)
         self.monitorTextOutbound.insert(END,outboundData)
         self.monitorTextInbound.config(state=DISABLED)
         self.monitorTextOutbound.config(state=DISABLED)

         self.highlightData(self.monitorTextInbound,inboundChangeLocations)
         self.highlightData(self.monitorTextOutbound,outboundChangeLocations)

         oldInbound = copy.deepcopy(currentInbound)
         oldOutbound = copy.deepcopy(currentOutbound)

         time.sleep(1)

   def parseData(self,data):
      text = ""
      for ip in data:
         total = 0
         text += ip+" <{}>\t\t\t"
         for port in data[ip]:
            num = data[ip][port]
            text += "{} <{}>\t\t".format(port,num)
            total += num
         text = text.format(total)+"\n"
      return text

   def getChanges(self,old,new):
      changes = {}
      for ip in new:
         ports = []
         for port in new[ip]:
            try:
               if new[ip][port] != old[ip][port]:
                  ports.append(port)
            except:
               ports.append(port)
         if ports != []:
            changes.update({ip:ports})
      return changes

   def getChangeLocations(self,data,changes):
      locations = []
      lineCount = 1
      try:
         for line in data.split("\n"):
            ip = line[:line.index(" ")]
            if ip in changes:
               lineCountStr = str(lineCount)+"."
               locations.append((lineCountStr+"0",lineCountStr+str(line.index("\t"))))
               for port in changes[ip]:
                  portLocation = line.index("\t"+str(port)+" ")+1
                  locations.append((lineCountStr+str(portLocation),lineCountStr+str(portLocation+line[portLocation:].index("\t"))))
            lineCount += 1
      except:
         pass
      return locations

   def highlightData(self,monitor,locations):
      for location in locations:
         monitor.tag_add("highlight",location[0],location[1])
      monitor.tag_config("highlight",foreground="red")
            
   def monitor(self,IP,sock):
      while True:
         try:
            packet = sock.recvfrom(65535)[0]
            ip_header = packet[0:20]
            ip_header = unpack("!BBHHHBBH4s4s",ip_header)
            ip_header_length = ((ip_header[0] & 0xF) * 4)
            tcp_header = packet[ip_header_length:ip_header_length+20]
            tcp_header = unpack("!HHLLBBHHH",tcp_header)
            src = socket.inet_ntoa(ip_header[8])
            dst = socket.inet_ntoa(ip_header[9])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            if dst == IP:
               if src not in self.inbound:
                  self.inbound.update({src:{}})
               if dst_port not in self.inbound[src]:
                  self.inbound[src].update({dst_port:0})
               self.inbound[src][dst_port]+=1
            else:
               if dst not in self.outbound:
                  self.outbound.update({dst:{}})
               if dst_port not in self.outbound[dst]:
                  self.outbound[dst].update({dst_port:0})
               self.outbound[dst][dst_port]+=1
         except:
            pass

if __name__ == "__main__":
   NetworkMonitor()
   
