Web Page Acquire
================

Acquire a web page or a browsing session for forensic use.

This tools stores all the objects and various metadata for forensic use.

## Prerequisites

You need Python3, Google Chrome, `ffmpeg`, `pdflatex` and `dumpcap` installed.
The needed Python libraries are listed in `requirements.txt`.
This tools works on MAC and Linux (no Windows).

Notes:

* To record the video, it uses `ffmpeg`. You should check that the correct screen is detected.

* To capture packets, it uses `dumpcap`. Check it can work without superuser privileges. If not, add the SUID bit to the `dumpcap` binary.


## Usage

On a command line, run: 

```
web-page-acquire.py [-h] [--mode {page,browsing}] [--page PAGE]
                           [--outdir OUTDIR] [--noscroll] [--userprofile]
                           [--forcescreen FORCESCREEN]
```

* `mode` can be `page` to acquire a specific page (that you must specify with the `--page` option) or `browsing`, to allow you to browse and acquire multiple pages.

* By default, WPA stores the output creating a folder in the current directory.
You can override this behavior with `--outdir OUTDIR`.

* By default, WPA scrolls  the page when in `page` mode to acquire the whole content.
You can prevent this with `--noscroll`.

* WPA autodetects the output screen. If it fails, force is with `--forcescreen FORCESCREEN`.

* By default, WPA opens a new Chrome profile, with no user data. You can use your default profile with `--userprofile`, to have access to your logins, etc.

**Note:** with `--userprofile`, you should close Chrome before starting.

## Output Files

WPA creates various output files, that are here listed:

* `urls.csv`: the list of downloaded URLs in csv.
* `{requests,responses}.json`: details of HTTP transactions
* `capture.pcap`: the network activity on the network during the acquisition
* `video.mkv`: the video of the operation
* `screenshot/*`: the screenshots of the page. More than one if the page has been scrolled.
* `objects/*`: all the downloaded objects.
* `log.txt`: the log of WPA during the acquisition.
* `log.pdf`: the log of WPA during the acquisition in PDF, containing all the checksums of the downloaded files.

## Recommendations

Create a ZIP archive of the generated files.
It is recommended to sign electronically the `log.pdf` to prove the acquisition files are not altered.



