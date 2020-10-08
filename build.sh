#!/bin/bash
#
# For a lazy, yet effective tight developer loop:
#
#   ./build.sh && $SPLUNK_HOME/bin/splunk install app $(<.release) -update 1

set -e

[[ -d "dist" ]] || mkdir dist


# Todo:  Refactor this so that the app and TA aren't stored in git twice (super painful version control); since most files are unchanged between the 2 use cases
ksconf package . \
    -f "dist/IMAPmailbox-{{version}}.tar.gz" \
    --app-name "IMAPmailbox" \
    --block-local \
    -b '.bumpversion.cfg' \
    -b '.gitignore' \
    -b '.pre-commit-config.yaml' \
    -b 'dist' \
    -b 'build.sh' \
    --release-file .release \
    --hook-script "cp bin/get_imap_email.py appserver/addons/IMAPmailbox-TA/bin/"
