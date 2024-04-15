# README

## Install

Install `mitmproxy` with pip and tmux.

## Usage

Open two tmux panes.

In one, run `mitmdump -s ./censor.py`.

In the other, run `curl --proxy http://127.0.0.1:8080 "https://www.google.com"` (will be blocked). Getting any other URL will work fine.
