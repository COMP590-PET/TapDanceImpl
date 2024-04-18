# README

## Install

`python -m pip install -r requirements.txt`. This exact command may not work if your Python environment is wonky, and if so, install however you normally use `pip`. Also consider using a [virtual environment](https://docs.python.org/3/library/venv.html).

You should also install tmux to see multiple terminal windows in the same terminal, though this isn't strictly necessary (you can just use multiple terminal windows instead).

## Usage

Open two tmux panes.

In one, run `mitmdump -s ./censor.py`.

In the other, run `curl --proxy http://127.0.0.1:8080 "http://www.google.com"`, which will be blocked since it's in `urls.txt`. Getting any other URL will work fine.
