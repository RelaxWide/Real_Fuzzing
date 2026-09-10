#!/usr/bin/env bash
# Build an additional Ubuntu/Debian test kernel; do not install or reboot.
set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
    echo 'Run this build as your normal user, without sudo.' >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_root=${1:-"${HOME}/nvme-fwtest-6.8.12"}
mkdir -p -- "$build_root"
build_root=$(cd -- "$build_root" && pwd)
source_dir="$build_root/linux-6.8.12"
running_release=$(uname -r)
config_file="/boot/config-$running_release"
jobs=${FWTEST_JOBS:-2}

if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
    echo 'FWTEST_JOBS must be a positive integer.' >&2
    exit 1
fi
if [[ $running_release != 6.8.12-060812* ]]; then
    echo "Expected the reported 6.8.12-060812 kernel; running: $running_release" >&2
    exit 1
fi
if [[ ! -r $config_file ]]; then
    echo "Cannot read running kernel configuration: $config_file" >&2
    exit 1
fi
for tool in curl tar xz patch python3 make cc dpkg-deb; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing dependency: $tool. Install the README build dependencies first." >&2
        exit 1
    fi
done
if [[ -e $source_dir ]]; then
    echo "Build directory already exists: $source_dir" >&2
    echo 'Use a different output directory to start a fresh build.' >&2
    exit 1
fi

archive="$build_root/linux-6.8.12.tar.xz"
curl --fail --location --retry 3 \
    https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.12.tar.xz \
    --output "$archive.part"
xz --test "$archive.part"
mv -- "$archive.part" "$archive"
tar -xJf "$archive" -C "$build_root"

# This check applies the patch only in a temporary copy and exercises the C policy.
python3 "$script_dir/check_policy.py" v6.8 "$source_dir"
cd -- "$source_dir"
patch --batch --fuzz=0 -p1 -i "$script_dir/nvme-persistent-error-test-policy-v6.8.patch"
cp -- "$config_file" .config
./scripts/config --set-str LOCALVERSION '' --disable LOCALVERSION_AUTO \
    --set-str SYSTEM_TRUSTED_KEYS '' --set-str SYSTEM_REVOCATION_KEYS '' \
    --disable DEBUG_INFO --disable DEBUG_INFO_BTF --disable DEBUG_INFO_BTF_MODULES \
    --enable DEBUG_INFO_NONE
make LOCALVERSION=-fwtest olddefconfig
release=$(make -s LOCALVERSION=-fwtest kernelrelease)
if [[ $release != 6.8.12-fwtest ]]; then
    echo "Unexpected kernel release: $release" >&2
    exit 1
fi
make -j"$jobs" LOCALVERSION=-fwtest KDEB_PKGVERSION=6.8.12-1 bindeb-pkg

# Install only this image and its headers, never linux-libc-dev or debug packages.
shopt -s nullglob
images=("$build_root"/linux-image-"$release"_*.deb)
headers=("$build_root"/linux-headers-"$release"_*.deb)
if (( ${#images[@]} != 1 || ${#headers[@]} != 1 )); then
    echo "Expected one kernel image and one headers package in $build_root" >&2
    exit 1
fi
installer="$build_root/install-fwtest.sh"
{
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    printf 'sudo dpkg -i'
    printf ' %q' "${images[@]}" "${headers[@]}"
    printf '\nsudo update-grub\n'
} > "$installer"
chmod +x "$installer"
printf '\nBuilt %s. Nothing has been installed.\n' "$release"
printf 'Install command: bash %q\n' "$installer"
printf 'Then select %s in GRUB and add the target-BDF parameter as documented.\n' "$release"
