# DVB-UECP-Tools
A collection of Python tools for processing UECP (and other) RDS data from inside satellite DVB MPEG-TS-based feeds.

Some of these tools require the PyAV library (FFMPEG bindings for Python). You can install this by running -
```
pip install av
```

## uecp_mp2.py
Decode UECP data from inside an MP2 audio stream, and display the decoded RDS in the terminal.

This script takes one argument (`-W`) for an HTTP stream containing MP2 with UECP data. I've tested this with raw MP2, MP2 via Icecast, and MP2 inside MPEG-TS (like the native HTTP output from an Enigma2 satellite receiver).

Usage:
```
python uecp_mp2.py -W <URL to stream containing MP2 service with UECP data>
```

## uecp_ts.py
Decode UECP data from a specific data PID inside an MPEG-TS stream, and display the decoded RDS in the terminal.

This script takes two arguments, the URL of the stream containing MPEG-TS data (`-W`), and the data PID inside which the RDS data to decode can be found (`-D`).

Usage:
```
python uecp_ts.py -W <URL> -D <PID>
```

## uecp_mp2_tcp.py, uecp_ts_tcp.py
These tools decode UECP from the respective stream formats as described above. They then additionally forward the UECP packets onto StereoTool, allowing the encoding and transmission of the RDS data dynamically.

Please see the files themselves for the available options.

## gedi2uecp_tcp.py
This tool does the same as the mp2_tcp and ts_tcp tools, but supports some Italian radio stations on Hotbird 13E 12149V that use a non-UECP format data stream to send RDS radio text data. This tool converts that data to UECP and allows it to be forwarded to StereoTool.

Please see the file itself for the available options.