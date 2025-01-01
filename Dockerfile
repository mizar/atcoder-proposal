FROM ubuntu:24.04
RUN apt-get update
RUN apt-get install -y --no-install-recommends sudo
RUN groupadd runner && \
    useradd -g runner -G sudo -m runner && \
    echo 'runner ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    mkdir /judge && \
    chown runner:runner /judge
COPY ./install-command.bash /tmp/
USER runner
WORKDIR /judge
RUN bash /tmp/install-command.bash
