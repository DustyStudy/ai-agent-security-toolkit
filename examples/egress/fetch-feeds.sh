#!/bin/sh
# Example feed job for the gateway's egress blocklist (docs/GATEWAY.md, "Egress blocklist").
# Run it from cron or a systemd timer on a host that holds the FEED key (never the policy
# bundle key, never the gateway host), then copy the files to the gateway's feed folder.
#
# The URLs below are placeholders. Take the current download URLs, formats and terms of use
# from each provider's own pages; some abuse.ch downloads need an Auth-Key. Accepting those
# terms is your decision.
set -eu

DEST=${DEST:-/var/lib/agentsec/feeds}
KEY=${KEY:-file:/etc/agentsec/feeds.key}   # Ed25519 private key PEM, as env:NAME or file:/path
DROP_URL=${DROP_URL:?set DROP_URL to the Spamhaus DROP list in "CIDR ; comment" text form}
HOSTS_URL=${HOSTS_URL:?set HOSTS_URL to an abuse.ch host list in hosts-file or one-domain-per-line form}

fetch() {  # fetch <name> <kind> <url> <file>
    tmp=$(mktemp "$DEST/.$1.XXXXXX")
    curl --fail --silent --show-error --proto '=https' --max-time 120 -o "$tmp" "$3"
    # Validates and signs; refuses (and signs nothing) if any line is malformed.
    agentsec egress sign-feed "$tmp" --kind "$2" --name "$1" --key "$KEY"
    # The signature names the list, not the file, so the pair can be renamed into place.
    # Signature first: until the feed itself is replaced the pair mismatches, and the gateway
    # keeps its last good list and retries on its next refresh.
    mv "$tmp.sig" "$DEST/$4.sig"
    mv "$tmp" "$DEST/$4"
}

fetch drop ip "$DROP_URL" drop.txt
fetch urlhaus domain "$HOSTS_URL" urlhaus-hosts.txt
