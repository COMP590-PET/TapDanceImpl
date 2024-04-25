# README

## Install

`python -m pip install -r requirements.txt`. This exact command may not work if your Python environment is wonky, and if so, install however you normally use `pip`. Also consider using a [virtual environment](https://docs.python.org/3/library/venv.html).

You should also install tmux to see multiple terminal windows in the same terminal, though this isn't strictly necessary (you can just use multiple terminal windows instead).

## Usage

Follow the usage instructions in [censor.py](censor.py) and [client.py](client.py).

You may also use `curl,` such as `curl --proxy http://127.0.0.1:8080 "http://www.google.com"`.

### Resources folder

There are some files in [resources/](resources) that you may have to generate yourself.

#### mitmproxy-ca-cert.pem

1. Run `mitmproxy`
2. Go to your computer's proxy settings (e.g., in [chrome://settings/system](chrome://settings/system)) and enable HTTP and HTTPS proxy servers on `127.0.0.1:8080`
3. Go to [mitm.it](mitm.it)
4. Generate a certificate for your OS
5. Save the file to [resources/](resources) with the same name to enable our code to work
6. To use in Google Chrome, you will have to double click the certificate and trust it (the steps depend on your OS)

## Testing

`python -m pytest tests`
