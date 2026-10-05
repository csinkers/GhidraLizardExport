set dotenv-load

[windows]
set shell := ["C:/Program Files/Git/bin/bash.exe", "-cu"]

# Assumes GHIDRA_INSTALL_DIR is set, or listed in .env
build: _checkGhidra
    @gradle -PGHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR} buildExtension

_checkGhidra:
    @if [ "${GHIDRA_INSTALL_DIR:-unset}" = "unset" ];                                                    \
    then                                                                                         \
        echo "GHIDRA_INSTALL_DIR not set, add a .env file with file paths or set environment variables"; \
        exit 1;                                                                                  \
    fi

    @if [ ! -d "${GHIDRA_INSTALL_DIR}" ]; then                       \
        echo "Ghidra directory \"${GHIDRA_INSTALL_DIR}\" not found"; \
        exit 1;                                              \
    fi


