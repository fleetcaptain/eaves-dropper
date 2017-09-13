# eaves-dropper
A script to extract mpeg audio files from network streams in real time.

DO NOT use this script for illegal purposes! Only use it on networks and/or devices for which you have ownership or permission to do so.

This script parses HTTP source port 80 traffic for MPEG audio files. Carved files can be saved and/or played automatically. The Scapy python module is required to run the script. The mpg123 program is not required, but unless you modify the script you will not be able to play extracted audio files in real time without it.

Script created to learn network packet programming with Scapy. Useful for auidibly demonstrating why HTTP is not as confidential as HTTPS...
