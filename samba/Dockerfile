# AORTA attacker-forest Samba AD DC.
# Base: instantlinux/samba-dc (Samba 4.23.x AD DC on Alpine). Upstream
# entrypoint.sh is kept (provisioning + smb.conf templating); we add debug
# tooling and a patched KDC library (see README).
FROM alpine:3.24 AS samba-builder

RUN apk add --no-cache alpine-sdk git sudo \
 && adduser -D builder \
 && addgroup builder abuild \
 && printf '%%abuild ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/abuild

USER builder
WORKDIR /home/builder
RUN git clone --depth 1 --filter=blob:none --sparse --branch 3.24-stable \
      https://gitlab.alpinelinux.org/alpine/aports.git \
 && cd aports \
 && git sparse-checkout set main/samba

COPY --chown=builder:builder 428bc209-ok-as-delegate-trusted-domains.patch \
    /home/builder/aports/main/samba/

RUN cd /home/builder/aports/main/samba \
 && sed -i '/disable-compile-error-test.patch/a\    428bc209-ok-as-delegate-trusted-domains.patch' APKBUILD \
 && abuild-keygen -a -n \
 && sudo cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/ \
 && abuild checksum \
 && sudo apk update \
 && abuild -r \
 && mkdir -p /home/builder/patched-lib \
 && apk_file="$(find /home/builder/packages -name 'samba-dc-libs-4.23.8-r0.apk' -print -quit)" \
 && test -n "$apk_file" \
 && tar -xzf "$apk_file" -C /home/builder/patched-lib \
      usr/lib/samba/libdb-glue-private-samba.so

FROM instantlinux/samba-dc:latest

COPY --from=samba-builder \
    /home/builder/patched-lib/usr/lib/samba/libdb-glue-private-samba.so \
    /usr/lib/samba/libdb-glue-private-samba.so

RUN apk add --no-cache \
      bind-tools \
      krb5 \
      openldap-clients \
      iproute2 \
      tcpdump \
      busybox-extras \
      libfaketime

LABEL org.opencontainers.image.title="aorta-samba-dc" \
      org.opencontainers.image.description="Samba AD DC for the AORTA attacker forest (BYTESTORM.LOCAL)" \
      org.opencontainers.image.source="https://github.com/0xNDI/aorta-linux-dc" \
      org.opencontainers.image.base.name="docker.io/instantlinux/samba-dc:latest" \
      aorta.realm="BYTESTORM.LOCAL"
