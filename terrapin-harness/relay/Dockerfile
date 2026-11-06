FROM python:3.12-slim
WORKDIR /app
COPY ssh_wire.py logger.py relay.py ./
ENTRYPOINT ["python3", "relay.py"]
