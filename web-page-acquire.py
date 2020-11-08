#!/usr/bin/env python3
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
import PyChromeDevTools
import subprocess
import platform
import argparse
import hashlib
import signal
import base64
import shutil
import glob
import json
import math
import time
import os
import re

# Constants
CHROME_MAC="/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome"
CHROME_LINUX = "google-chrome"
SHORT_TIMEOUT=2
LONG_TIMEOUT=10
MAX_FILE_LEN=50

screen_cnt = 0
file_cnt = 0
urls=[]
request_headers=[]
response_headers=[]
log_f = None

def pre_start():
    global log_f

    # Make outpath dir
    os.mkdir(outpath)
    os.mkdir(os.path.join(outpath,"screenshots"))
    os.mkdir(os.path.join(outpath,"objects"))
    log_f = open(os.path.join(outpath,"log.txt") , "w")
    log("Output path: {}".format(outpath))

    # Start TCPDump
    start_tcpdump()

    # Start FFMpeg
    start_ffmpeg()

def start_tcpdump():
    global proc_tcpdump
    global outpath
    CMD = "dumpcap -w {}".format(os.path.join(outpath, "capture.pcap"))
    FNULL = open(os.devnull, 'w')
    proc_tcpdump = subprocess.Popen(CMD, shell=True, stdin=None, stdout=FNULL, 
                            stderr=subprocess.STDOUT, close_fds=True, preexec_fn=os.setsid)

def start_ffmpeg():
    global proc_ffmpeg
    if platform == "Linux":
        CMD = "ffmpeg -y -framerate 10 -f avfoundation -i '1:' {}".format(os.path.join(outpath, "video.mkv"))
    else:
        video_device = subprocess.check_output('ffmpeg -f avfoundation -list_devices true -i "" 2>&1 | grep "Capture screen" | grep --color=never -o "\[[0-9]\]"  | tr -d []', shell = True).decode("ascii").strip()
        log("Video Device: {}".format(video_device))
        CMD = "ffmpeg -y -framerate 10 -f avfoundation -i '{}:' {}".format(video_device, os.path.join(outpath, "video.mkv"))
    FNULL = open(os.devnull, 'w')
    proc_ffmpeg = subprocess.Popen(CMD, shell=True, stdin=None, stdout=FNULL, 
                            stderr=subprocess.STDOUT, close_fds=True, preexec_fn=os.setsid)    


def start_chrome():
    global proc
    global profile_dir
    # Start a process
    profile_dir="/tmp/wpa_" + time_s
    chrome_bin = CHROME_LINUX if platform == "Linux" else CHROME_MAC
    profile = "" if userprofile else "--user-data-dir={}".format(profile_dir)

    CHROME_CMD="{} --remote-debugging-port=9222 {} --no-first-run about:blank".format(chrome_bin, profile)
    FNULL = open(os.devnull, 'w')
    proc = subprocess.Popen(CHROME_CMD, shell=True, stdin=None, stdout=FNULL, 
                            stderr=subprocess.STDOUT, close_fds=True, preexec_fn=os.setsid)
    time.sleep(SHORT_TIMEOUT)

def process_messages(messages):
    global urls
    global request_headers
    global response_headers

    for m in messages:
        if "method" in m and m["method"] == "Network.responseReceived":
            try:
                url=m["params"]["response"]["url"]

                if not url.startswith("data:"):
                    timestamp = m["params"]["response"]["responseTime"]
                    ip = m["params"]["response"]["remoteIPAddress"]
                else:
                    timestamp = time.time()
                    ip = "-"
                mimeType = m["params"]["response"]["mimeType"]
                urls.append((timestamp,url,ip,mimeType))

                request_id = m["params"]["requestId"]
                save_obj(url, request_id)

                response_headers.append(m["params"]["response"])

            except Exception as e:
                log("Error: {} in URL: {}".format(e,m["params"]["response"]["url"]))           
        elif "method" in m and m["method"] == "Network.requestWillBeSent":
            try:
                request_headers.append(m["params"]["request"])
            except Exception as e:
                log(e)   



def save_obj(url, request_id):
    global file_cnt
    res, msg = chrome.Network.getResponseBody(requestId=request_id)
    process_messages(msg)
    content = res['result']['body']
    filename = os.path.basename(urlparse(url).path)
    final_path = os.path.join(outpath,"objects","{}-{}".format(file_cnt,filename[:MAX_FILE_LEN]))
    if res['result']['base64Encoded']:
        with open(final_path, "wb") as f:
            f.write(base64.b64decode(content))
    else:
        with open(final_path, "w") as f:
            f.write(content)
    file_cnt +=1

def make_screenshot():
    global screen_cnt
    res, msg = chrome.Page.captureScreenshot()
    imgb64 = res['result']['data']
    with open(os.path.join(outpath,"screenshots","{}.png".format(screen_cnt)),  "wb" ) as f:
        f.write(base64.b64decode(imgb64))
    screen_cnt +=1
    process_messages(msg)

def kill_chrome():
    global proc
    global profile_dir
    # Kill Chrome and delete profile
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    shutil.rmtree(profile_dir, ignore_errors=True)

def post_end():
    global urls

    # Stop TCPDump
    stop_tcpdump()

    # Stop FFMpeg
    stop_ffmpeg()

    # Save urls
    df_urls  = pd.DataFrame(urls, columns=["timestamp", "url", "remote_ip",  "mime_type"]).sort_index()
    df_urls.to_csv(os.path.join(outpath,"urls.csv"))

    # Save  Requests
    with open(os.path.join(outpath,"requests.json"), "w") as f:
        json.dump(request_headers, f, indent=4)

    # Save  Reponses
    with open(os.path.join(outpath,"responses.json"), "w") as f:
        json.dump(response_headers, f, indent=4)

def stop_tcpdump():
    global proc_tcpdump
    try:
        os.killpg(os.getpgid(proc_tcpdump.pid), signal.SIGTERM)
    except Exception as e:
        log("Exception in terminating TCPDump: {}".format(e))   

def stop_ffmpeg():
    global proc_ffmpeg

    try:
        os.killpg(os.getpgid(proc_ffmpeg.pid), signal.SIGTERM)
    except Exception as e:
        log("Exception in terminating FFMPeg: {}".format(e))   

def check_ok():
    errors = False

    if os.path.isfile(os.path.join(outpath, "screenshots/0.png")):
        log("Screenshot file OK")
    else:
        log("Screenshot file ERROR")
        errors = True

    if os.path.isfile(os.path.join(outpath, "video.mkv")):
        log("video file OK")
    else:
        log("video file ERROR")
        errors = True

    if os.path.isfile(os.path.join(outpath, "capture.pcap")):
        log("Capture file OK")
    else:
        log("Capture file ERROR")
        errors = True

    if os.path.isfile(os.path.join(outpath, "requests.json")):
        log("Request file OK")
    else:
        log("Request file ERROR")
        errors = True

    if os.path.isfile(os.path.join(outpath, "responses.json")):
        log("Responses file OK")
    else:
        log("Responses file ERROR")
        errors = True

    if os.path.isfile(os.path.join(outpath, "urls.csv")):
        log("URL file OK")
    else:
        log("URL file ERROR")
        errors = True

    if errors:
        print("ERROR!!! One or more files missing.")
        print("===================================")
    else:
        print("OK, the acquisition is valid")
        print("============================")


def create_checksums():

    global hashes
    hashes = {}
    for f_name in [     os.path.join(outpath, "responses.json"),
                        os.path.join(outpath, "requests.json"),
                        os.path.join(outpath, "urls.csv"),
                        *glob.glob(os.path.join(outpath, "screenshots/*")),
                        *glob.glob(os.path.join(outpath, "objects/*"))]:

        with open(f_name,"rb") as f:
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest();
            hashes[f_name] = readable_hash
            log_only_file("File: {} - SHA256: {}".format(f_name, readable_hash))


def tex_escape(text):
    """
        :param text: a plain text message
        :return: the message escaped to appear correctly in LaTeX
    """
    conv = {
        '&': r'\&',
        '%': r'\%',
        '$': r'\$',
        '#': r'\#',
        '_': r'\_',
        '{': r'\{',
        '}': r'\}',
        '~': r'\textasciitilde{}',
        '^': r'\^{}',
        '\\': r'\textbackslash{}',
        '<': r'\textless{}',
        '>': r'\textgreater{}',
    }
    regex = re.compile('|'.join(re.escape(str(key)) for key in sorted(conv.keys(), key = lambda item: - len(item))))
    return regex.sub(lambda match: conv[match.group()], text)

def txt2pdf(f_in, f_out):
    
    PREAMBLE="""\\documentclass{article}
                \\usepackage{graphicx}
                \\begin{document}
                \\subsection*{Web Page Acquire Summary}
                \\noindent\n"""
    POST="""\n\\end{document}"""

    f_tmp = os.path.join("/tmp", "wpa.tex")
    f = open(f_tmp, "w")
    f.write(PREAMBLE)
    for line in open(f_in,"r").read().splitlines():
        print(tex_escape(line), "\n", file = f)
    f.write(POST)
    f.close()

    subprocess.check_output("pdflatex -interaction=nonstopmode -output-directory=/tmp {}".format(os.path.join("/tmp", "wpa.tex")), shell=True)
    shutil.copyfile(os.path.join("/tmp", "wpa.pdf"), f_out)


def main():

    global outpath
    global time_s
    global this_platform
    global proc
    global profile_dir
    global chrome
    global log_f

    log("Starting")

    # Parse Vars
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', type=str, default='page',  choices=['page', 'browsing'])
    parser.add_argument('--page', type=str, default=None)
    parser.add_argument('--outdir', type=str, default=".")
    parser.add_argument('--noscroll', action='store_true')
    parser.add_argument('--userprofile', action='store_true')

    globals().update(vars(parser.parse_args()))

    # Check OS
    this_platform = platform.system()
    if this_platform == "Windows":
        print ("Windows not supported. Quitting...")
        return

    if page is None and mode == "page":
        print ("Page must be specified when in page mode. Quitting...")
        return

    if page is not None and mode == "page" and \
        not ( page.startswith("https://") or page.startswith("http://") ):  
        print ("Pages must begin by http:// or https:// . Quitting...")
        return       

    # Define Path
    time_s = time.strftime('%Y-%m-%d_%H-%M-%S')
    outpath = os.path.join(outdir, time_s)

    # Pre Start
    pre_start()
    log("Started TCPDump and FFMpeg")

    # Start Chrome
    start_chrome()
    time.sleep(SHORT_TIMEOUT)
    log("Started Chrome")

    # Open Channel to Chrome
    chrome = PyChromeDevTools.ChromeInterface(auto_connect=False)
    chrome.get_tabs()
    tabs = chrome.tabs
    for i, tab in enumerate(tabs):
        if tab["url"] == 'about:blank':
            break
    chrome.connect(tab=i)
    chrome.Network.enable()
    chrome.Page.enable()

    # Navigate to start URL and wait it to load
    if page is not None:
        result, messages_early = chrome.Page.navigate(url=page)
        #process_messages(messages)
        _,messages=chrome.wait_event("Page.frameStoppedLoading", timeout=LONG_TIMEOUT)
        process_messages(messages_early + messages)
        log("Navigated to URL: {}".format(page))

        if mode=="page":
            res, msg = chrome.Page.getLayoutMetrics()
            process_messages(msg)
            contentHeight = res["result"]['contentSize']['height']
            clientHeight  = res["result"]['visualViewport']['clientHeight']
            scrolls = math.ceil((contentHeight-clientHeight)/clientHeight)+1
            log("View Heigth: {}, Page Heigth: {}, making {} scrolls".format(clientHeight, contentHeight, scrolls))

            make_screenshot()

            if noscroll:
                scrolls = 0

            for i in range( scrolls):
                chrome.Input.synthesizeScrollGesture(x=100,y=100, xDistance=0, yDistance=-clientHeight, speed=clientHeight*100)
                time.sleep(SHORT_TIMEOUT)
                make_screenshot()
                
            messages=chrome.pop_messages()
            process_messages(messages)

        elif mode=="browsing":
            pass

    log("Quitting Chrome")
    kill_chrome()

    log("Running Final Operations")
    post_end()

    log("Checking the output")
    check_ok()

    log("Creating Checksums")
    create_checksums()

    log("Creating PDF")
    log_f.flush()
    try:
        txt2pdf(os.path.join(outpath,"log.txt"), os.path.join(outpath,"log.pdf"))
    except Exception as e:
        log("Error Creating the PDF: {}. Quitting...".format(e))
        return

    log("PDF Proof in: {}".format(os.path.join(outpath,"log.pdf")))
    log("Now you shall sign it electronically")
    log("Done")

def log(str):
    print(datetime.now().strftime("[%Y-%m-%d %H:%M:%S]"), str)
    if log_f is not None:
        print(datetime.now().strftime("[%Y-%m-%d %H:%M:%S]"), str, file=log_f)

def log_only_file(str):
    if log_f is not None:
        print(datetime.now().strftime("[%Y-%m-%d %H:%M:%S]"), str, file=log_f)


if __name__ == "__main__":
    main()

