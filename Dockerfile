# Key server image:  docker build -t zknbed .  &&  docker run -v zknbe-data:/var/lib/zknbe -p 7421:7421 zknbed
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p zknbe-server

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/zknbe --shell /usr/sbin/nologin zknbe \
    && install -d -o zknbe -g zknbe -m 0700 /var/lib/zknbe
COPY --from=build /src/target/release/zknbed /src/target/release/zknbectl /usr/bin/
USER zknbe
VOLUME /var/lib/zknbe
# 7421: device API. The admin API stays on loopback inside the container:
#   docker exec <container> zknbectl status
EXPOSE 7421
ENTRYPOINT ["/usr/bin/zknbed"]
