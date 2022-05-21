# Socket communication

## 1. Generate Client Keys
- Make script executable
    - `chmod u+x ./cer-gen.sh`
- Run script wtih client domain name as argument
    - `./cer-gen.sh <domain-name>`

## 2. Connect to the server
- Run server:
    - `python3 tlsChatServer.py`
- Run client:
    - `python3 tlsChatClient.py`