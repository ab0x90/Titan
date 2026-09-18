#!/usr/bin/env bash
# install.sh — install Titanis (if needed) + titan wrapper
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
WRAPPER="${BIN_DIR}/titan"

TITANIS_DOWNLOAD_URL="https://github.com/mattmillen15/Titanis/releases/download/v0.9.262-tsch/Titanis-tools-linux-x64-net8.zip"
TITANIS_INSTALL_DIR="${HOME}/tools/titanis"

# ── .NET 8 runtime ────────────────────────────────────────────────────────────

DOTNET_ROOT_FOUND=""

find_dotnet() {
    for d in "${DOTNET_ROOT:-}" "${HOME}/.dotnet" "/usr/share/dotnet" "/usr/local/share/dotnet"; do
        [[ -z "${d}" ]] && continue
        if ls "${d}/shared/Microsoft.NETCore.App/" 2>/dev/null | grep -q "^8\."; then
            echo "${d}"; return 0
        fi
    done
    # Check /etc/dotnet/install_location
    if [[ -f /etc/dotnet/install_location ]]; then
        loc="$(cat /etc/dotnet/install_location)"
        if ls "${loc}/shared/Microsoft.NETCore.App/" 2>/dev/null | grep -q "^8\."; then
            echo "${loc}"; return 0
        fi
    fi
    return 1
}

if DOTNET_ROOT_FOUND="$(find_dotnet)"; then
    echo "[+] .NET runtime: ${DOTNET_ROOT_FOUND}"
else
    echo "[*] .NET 8 not found — installing..."
    command -v curl &>/dev/null || { echo "[!] curl required to install .NET" >&2; exit 1; }
    TMP_DOTNET_INSTALL="/tmp/dotnet-install-$$.sh"
    curl -fsSLk https://dot.net/v1/dotnet-install.sh -o "${TMP_DOTNET_INSTALL}"
    chmod +x "${TMP_DOTNET_INSTALL}"
    # Strip set -u — hits unbound associative array key on some bash versions
    sed -i -e 's/set -euo pipefail/set -eo pipefail/g' \
           -e 's/^set -u$/set +u/' \
           "${TMP_DOTNET_INSTALL}"
    # dotnet-install.sh uses $() subshells to build download URLs.
    # If run inside proxychains, "[proxychains] DLL init" messages go to
    # stderr and get captured into those subshells, corrupting the URL.
    # Strip LD_PRELOAD so the script runs clean.
    env -u LD_PRELOAD bash "${TMP_DOTNET_INSTALL}" --runtime dotnet --version 8.0.0
    rm -f "${TMP_DOTNET_INSTALL}"
    DOTNET_ROOT_FOUND="${HOME}/.dotnet"
    echo "[+] .NET 8 installed: ${DOTNET_ROOT_FOUND}"
    # Register so framework-dependent apps find it without DOTNET_ROOT
    if mkdir -p /etc/dotnet 2>/dev/null && [[ -w /etc/dotnet ]]; then
        echo "${DOTNET_ROOT_FOUND}" > /etc/dotnet/install_location
        echo "[+] Registered: /etc/dotnet/install_location"
    fi
fi

# ── Titanis binaries ──────────────────────────────────────────────────────────

TITANIS_ROOT=""
for candidate in "${TITANIS_PATH:-}" \
                 "${TITANIS_INSTALL_DIR}/linux-x64" \
                 "${REPO_DIR}/../titanis/linux-x64"; do
    [[ -z "${candidate}" ]] && continue
    if [[ -d "${candidate}" ]] && [[ -f "${candidate}/Smb2Client/Smb2Client" ]]; then
        TITANIS_ROOT="${candidate}"
        break
    fi
done

if [[ -z "${TITANIS_ROOT}" ]]; then
    echo "[*] Titanis not found — downloading..."
    command -v curl  &>/dev/null || { echo "[!] curl required" >&2; exit 1; }
    command -v unzip &>/dev/null || { echo "[!] unzip required" >&2; exit 1; }

    TMP_ZIP="/tmp/Titanis-linux-x64-$$.zip"
    curl -fLk --progress-bar -o "${TMP_ZIP}" "${TITANIS_DOWNLOAD_URL}"
    mkdir -p "${TITANIS_INSTALL_DIR}"
    unzip -q -o "${TMP_ZIP}" -d "${TITANIS_INSTALL_DIR}"
    rm -f "${TMP_ZIP}"

    # Make ELF binaries executable
    while IFS= read -r -d '' f; do
        case "$(basename "${f}")" in *.so|*.dll|*.pdb|*.json|*.xml|*.md|createdump) continue ;; esac
        file "${f}" 2>/dev/null | grep -q "ELF" && chmod +x "${f}"
    done < <(find "${TITANIS_INSTALL_DIR}" -maxdepth 5 -type f -print0)

    TITANIS_ROOT="${TITANIS_INSTALL_DIR}/linux-x64"
    echo "[+] Titanis installed: ${TITANIS_ROOT}"
fi

echo "[+] Titanis root: ${TITANIS_ROOT}"

# ── titan wrapper ─────────────────────────────────────────────────────────────

mkdir -p "${BIN_DIR}"

cat > "${WRAPPER}" <<WRAPPER_EOF
#!/usr/bin/env bash
export DOTNET_ROOT="${DOTNET_ROOT_FOUND}"
export PATH="${DOTNET_ROOT_FOUND}:\${PATH}"
export TITANIS_PATH="${TITANIS_ROOT}"
exec python3 "${REPO_DIR}/titan.py" "\$@"
WRAPPER_EOF

chmod +x "${WRAPPER}"
echo "[+] Installed: ${WRAPPER}"

# Ensure ~/.local/bin is on PATH
for rc in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
    if [[ -f "${rc}" ]] && [[ -w "${rc}" ]] && ! grep -q 'local/bin' "${rc}" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${rc}"
        echo "[+] Added ~/.local/bin to PATH in ${rc}"
    fi
done

echo ""
echo "[+] Done. Restart your shell or run: source ~/.zshrc"
echo ""
echo "    titan dump -h"
echo "    titan shell -h"
echo "    titan rbcd -h"
