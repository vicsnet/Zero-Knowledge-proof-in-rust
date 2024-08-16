FROM rust:1.70

WORKDIR /zkp-server

COPY ..

RUN cargo build --release --bin server --bin client