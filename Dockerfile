FROM rust

LABEL maintainer="hongsea@koompi.org"
WORKDIR /var/www/app/
COPY . .

RUN cd /var/www/app/game-back-end &&rustup default nightly && cargo build --release
EXPOSE 9000

