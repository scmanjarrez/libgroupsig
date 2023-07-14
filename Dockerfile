FROM ubuntu:jammy

RUN apt update && apt install -y build-essential gdb cmake vim libgmp-dev libssl-dev git

WORKDIR /mnt

