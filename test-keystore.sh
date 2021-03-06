#!/usr/bin/env bash

JVM_OPTS_SECURITY_DEBUG="-Djava.security.debug=all -Djavax.net.debug=all"
JVM_OPT_FIPS_MODE="-Dcom.safelogic.cryptocomply.fips.approved_only=true"
JVM_OPTS="$JVM_OPTS_SECURITY_DEBUG $JVM_OPT_FIPS_MODE"

. ./cluster-config.sh
. ./common.sh
launch_security_test