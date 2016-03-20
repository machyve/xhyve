#!/bin/bash

set -e -x

if [[ -d "${SRCROOT}/.git" ]] ; then
    VERSION=$(GIT_DIR="${SRCROOT}"/.git git describe --abbrev=6 --dirty --always --tags)
else
    VERSION="v${CURRENT_PROJECT_VERSION}"
fi

echo "#define VERSION \"${VERSION}\"" > "${DERIVED_FILE_DIR}/xhyve-version.h"
