#!/bin/sh
# Add the signed os-shopguard package repository to OPNsense and install the plugin
# (as root). Run it once: the plugin is then listed under System > Firmware > Plugins
# and its updates come with the OPNsense updates (System > Firmware > Updates).
#
#   fetch -o - https://raw.githubusercontent.com/Aarklendoia/shopguard/main/plugin/install.sh | sh
#
# Running it again is harmless. It also moves an install made by hand (pkg add) to the
# repository.
#
#   SHOPGUARD_REPO    GitHub repository of a fork (default: Aarklendoia/shopguard); its
#                     GitHub Pages serve the package repository
#   SHOPGUARD_PUBKEY  public key file of a fork's repository (default: the key below)
#   SHOPGUARD_URL     package repository URL (default: the GitHub Pages of SHOPGUARD_REPO),
#                     e.g. a local copy for tests: file:///path/to/repo
set -eu

REPO=${SHOPGUARD_REPO:-Aarklendoia/shopguard}
PKG=os-shopguard
NAME=ShopGuard
CONF=/usr/local/etc/pkg/repos/$NAME.conf
KEY=/usr/local/etc/ssl/$NAME.pub

[ "$(id -u)" -eq 0 ] || { echo "Must be run as root." >&2; exit 1; }

owner=$(echo "${REPO%%/*}" | tr '[:upper:]' '[:lower:]')
URL=${SHOPGUARD_URL:-"https://$owner.github.io/${REPO#*/}/pkg"}

# Signing key of the Aarklendoia/shopguard package repository (not the apu-firmware one).
# The CI checks that it matches the private key the repository is signed with.
# BEGIN PUBLIC KEY
DEFAULT_KEY='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7fIwZ41brqsooVHVVcKH
V+5GAXLRL8a4ZSnSdjXZNifjagcZuSbWbzt2Ja7TnJaWBZ+N0SCLLpgthIIXeOzL
fy9GJl7GQAe9ZcFyk5pnW0LfL+uHbJVTM7RAK2smej78BMzMGJe8TiLQUcNHa/Tv
kNRgB4xFymAY/SBfUICCHb/kGOPPGiE5KOnE/4Bx8p9SkXdAc5HEgpZkZReGM2LI
6IybpoWdK6hCD/9lp2Fbx9U3S2ByuQ/5tPLegI0duuNvNOqt+bQXCJr5bu7iXV85
yJEp1uDd8bXWgAw2BfFxo0/ahNqenPZiypW7PZadL0AjO4uwg1DxyDeTHjU30RUD
EJuBBSqlNJGEaP7dEwNYo9z4Lqc+8scB3v50lhyO2tbtT8tjLC/B2ZanwbKgJ34x
9K1/ITc3rO85E9zBFk+09EkJNZSxRrfjmv4aXb4D5pqVkGcOn+FJ8E/obhTUTghv
F3V4OtZT6QjrJewwmCF+jHktUZKPvv3G8VS9cV+mV7/MV7kyv3QFknoKDM8gELEb
d7uzwp3+nAlVyLi+dyaB9kaOlBKaZ7V3vC1/nY3/5oMU0JBEU1lFWOC7SZ1+aEl7
B2zb6Yp6PzewCczkvzpMeAwJRxNSlvLUtZ/a8f3Nunl8EOAYD952quPFPo3jPoBR
PJ/d65/oqgvtuRrbX4N4eCsCAwEAAQ==
-----END PUBLIC KEY-----'
# END PUBLIC KEY

mkdir -p "${KEY%/*}"
if [ -n "${SHOPGUARD_PUBKEY:-}" ]; then
    cp "$SHOPGUARD_PUBKEY" "$KEY"
elif [ "$REPO" = Aarklendoia/shopguard ]; then
    printf '%s\n' "$DEFAULT_KEY" > "$KEY"
else
    echo "A fork needs its own key: set SHOPGUARD_PUBKEY to its public key file." >&2
    exit 1
fi
chmod 644 "$KEY"

mkdir -p "${CONF%/*}"
cat > "$CONF" <<EOF
$NAME: {
  url: "$URL",
  signature_type: "pubkey",
  pubkey: "$KEY",
  mirror_type: "none",
  enabled: yes
}
EOF
echo "Package repository $NAME: $URL"

pkg update -f -r "$NAME"
version=$(pkg rquery -r "$NAME" %v "$PKG")
[ -n "$version" ] || { echo "$PKG not found in $URL." >&2; exit 1; }
installed=$(pkg query %v "$PKG" 2>/dev/null || true)
# pkg records the repository a package comes from in its "repository" annotation
from=$(pkg annotate -Sq "$PKG" repository 2>/dev/null || true)

# an install made by hand (pkg add) stays tied to no repository, even when reinstalled:
# remove it first, like "make upgrade" in opnsense/plugins. The settings stay in config.xml.
if [ -n "$installed" ] && [ "$from" != "$NAME" ]; then
    echo "Moving $PKG $installed (${from:-installed by hand}) to the $NAME repository"
    pkg delete -fy "$PKG"
fi

if [ "$(pkg query %v "$PKG" 2>/dev/null || true)" = "$version" ]; then
    echo "$PKG $version is already installed from $NAME."
else
    # -r: the plugin has no dependency outside OPNsense itself
    pkg install -y -r "$NAME" "$PKG"
fi

# record the plugin in config.xml, as System > Firmware > Plugins does, otherwise it is
# listed as "misconfigured"
/usr/local/opnsense/scripts/firmware/register.php install "$PKG"
service configd restart

echo
echo "$PKG ${installed:+$installed -> }$version installed from $NAME."
echo "Configure it under Services > ShopGuard, and enable the Unbound statistics"
echo "(Reporting > Settings) it reads the domains from. Updates come with the OPNsense updates."
