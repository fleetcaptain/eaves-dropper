# eaves-dropper
A script to extract mpeg audio files from network streams in real time.

DO NOT use this script for illegal purposes! Only use it on networks and/or devices for which you have ownership or permission to do so! 

This script parses HTTP (source port 80, to be precise) traffic for MPEG audio files. Files are saved to the output directory of your choice and can also be played automatically. I developed the script to extract and play the word pronounciation audio that the Words With Friends mobile game downloads when the user finds a word in the dictionary. As of 3/7/16, the script can parse audio from WWF version 3.210.2850, on a Motorola Moto G ("osprey") running CyanogenMod 12.1. Other versions of WWF and other platforms (iOS, Windows, etc.) have not been tested and I don't know if they work. Theoretically, the script should parse any mpeg files from any HTTP stream; I just haven't tested it on anything other than WWF.

The Scapy python module is required to run the script. The mpg123 program is not required, but unless you modify the script you will not be able to play extracted audio files in real time without it.

The script was a great learning experience as far as network packet programming. It is great for personal amusement and impressing friends and relatives. :)

Thank you for reading!

John 3:16
