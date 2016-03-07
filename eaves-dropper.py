'''
This script sniffs network traffic for HTTP and extracts mpeg audio files from it (if HTTP stream is unencrypted)
The script *should* work for any HTTP stream; however, I purely developed it for and tested it with network traffic for the
'Words With Friends' mobile game. The WWF app (at least for Android at the time of this script) would send an mpeg audio file
for a word when the user clicked the sound icon in the dictionary entry for the word. I developed this app to sniff for the 
mpeg file and play it. 

The script is mostly for amusement, but can be used to illustrate in an audible fashion that unencrypted traffic means, well, the traffic 
is unencrypted! 

DO NOT use this script for illegal purposes! Only use it on networks and/or devices for which you have ownership or permission to do so!
'''

from random import randint
import os, optparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #get rid of scapy's "Warning: no default route for IPv6" (is annoying to see everytime...)
from scapy.all import *

MPEG = 'Content-Type: audio/mpeg' #HTTP content type that we scan for in each packet
play_audio = True #default = play audio file when fully sniffed
interface = ''
outdir = ''
data_array = [] #holds the file data extracted from packets
ack_array = [] #holds the TCP ACK numbers for the TCP stream(s) containing mpeg audio (so we don't parse data from other streams, like webpages)

#last_seq_array is important
#when victim traffic is going through local PC (via arpspoof or similiar), it is possible the packet will be picked up by the script twice:
#1) when entering the interface (like from the router) and 2) when leaving this PC headed for the victim
#by keep track of sequence numbers, we can detect duplicate packets and ignore them
last_seq_array = []

#TCP flags. PSH, FIN are the only ones used right now. Rest are here merely for reference and quick use if needed later for some reason
#FIN = finished sending file, PSH = push (file pushed to user/client device)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

#action here
def parse(pkt):

	global data_array
	global ack_array
	global last_seq_array
	global MPEG
	global play_audio
	global outdir
	
	#if packet is TCP and is carrying 'cargo'
	if (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
		if pkt[TCP].sport == 80: #if it's source port 80 (scapy sniff function filter setup in main code should ensure this, but check anyway)
			data = str(pkt[TCP].payload)
			if MPEG in data and pkt[TCP].ack not in ack_array: #new packet
				http = data.split('\r\n\r\n')
				data_array.append(http[1])
				ack_array.append(pkt[TCP].ack)
				last_seq_array.append(pkt[TCP].seq)
				#print 'Got an ack: ' + str(pkt[TCP].ack)
				#print 'MPEG detected\tACK ' + str(pkt[TCP].ack)
			else:
				for x in range(0, len(ack_array)):
					if pkt[TCP].ack == ack_array[x] and pkt[TCP].seq != last_seq_array[x]: 
						#is previously flagged packet and not a repeat
						
						#add it's data to it's data_array	
						data_array[x] = data_array[x] + data
						last_seq_array[x] = pkt[TCP].seq #update the last sequence number for duplicate checking purposes
						F = pkt[TCP].flags
						if F & PSH or F & FIN:
							#no more data for this stream - file has been completely sent
							print 'MPEG file carved, TCP ACK ' + str(pkt[TCP].ack)
							audio = data_array[x] #audio = mpeg file
							filepath = outdir + 'audio_' + str(randint(1, 1000)) + '.mpeg' #use a random number generator try and get unique names for each file we save
							outfile = open(filepath, 'wr')
							outfile.write(audio)
							outfile.close()

							#play audio if not forbidden by user
							if play_audio:
								os.system('mpg123 -q ' + filepath)
							#this file has been completely sent, remove it from our tracking arrays
							data_array.pop(x)
							ack_array.pop(x)
							last_seq_array.pop(x)



#option parsing
#interface, output directory for sniffed files, and play or no play sniffed audio
parser = optparse.OptionParser('Usage: -i <interface> -o <output directory> (--no-play)')
parser.add_option('-i', dest='intface', type='string', help='interface to sniff on')
parser.add_option('-o', dest='output', type='string', help='output directory for sniffed audio files')
parser.add_option('--no-play', dest='play_aud', action='store_false', default=True, help="do not play audio as its' sniffed")
(options, args) = parser.parse_args()

#user must specify an interface to sniff on
if options.intface == None:
        print 'You must specify an interface to sniff on!'
        print "Use '-h' for more information"
        exit()
else:
        interface = options.intface

#if user doesn't specify a directory to output parsed mpeg files, default to /tmp
if options.output == None:
        print 'No output directory specified, using default of /tmp/'
        outdir = '/tmp/'
else:
        outdir = options.output

#defaults to True if user doesn't specify; will play mpeg files using mpg123 via commandline
play_audio = options.play_aud

print 'eaves-dropper - Python script for sniffing mpeg files from HTTP traffic'
print 'Use only on networks/devices for which you have ownership or permission to do so'
print 'DO NOT use for illegal purposes!\n'
if (play_audio):
	print "Audio will be played as it's sniffed. You need to have mpg123 installed for this to work."
else:
	print 'Sniffed audio will not be played'
print 'Sniffing for mpeg audio on ' + interface + '...'
sniff(iface=interface,filter="tcp port 80",prn=parse)

#it is possible to parse audio from a pcap file (was used early on for debugging purposes)
'''
pkts = rdpcap('/root/tools/packet_dumps/words.pcap')
for p in pkts:
	parse(p)
'''
