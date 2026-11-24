ARG SDS_BASE_IMAGE=sds-sunshine-deps:26.04
FROM ${SDS_BASE_IMAGE}

# Private test image only. Keep the live host and its package database untouched.
# Package candidates were read from the pinned Sunshine image on 2026-11-22.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qt6-declarative-dev=6.10.2+dfsg-3 \
    qt6-declarative-dev-tools=6.10.2+dfsg-3 \
    qml6-module-qtquick-controls=6.10.2+dfsg-3 \
    qml6-module-qtquick-templates=6.10.2+dfsg-3 \
    qml6-module-qtquick-layouts=6.10.2+dfsg-3 \
    qml6-module-qtqml-models=6.10.2+dfsg-3 \
    qml6-module-qtqml-workerscript=6.10.2+dfsg-3 \
    qml6-module-qtquick-window=6.10.2+dfsg-3 \
    qml6-module-qtquick=6.10.2+dfsg-3 \
    libsdl2-dev=2.32.10+dfsg-6 \
    libsdl2-ttf-dev=2.24.0+dfsg-3 \
    libavcodec-dev=7:8.0.1-3ubuntu2 \
    libavutil-dev=7:8.0.1-3ubuntu2 \
    libswscale-dev=7:8.0.1-3ubuntu2 \
    libgl1-mesa-dri=26.0.8-1ubuntu0.3 \
    libglx-mesa0=26.0.8-1ubuntu0.3 \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash"]
