#!/usr/bin/env bash

JVM_OPTS_SECURITY_DEBUG="-Djava.security.debug=all -Djavax.net.debug=all"
JVM_OPT_FIPS_MODE="-Dcom.safelogic.cryptocomply.fips.approved_only=true"
JVM_OPT_TRUSTSTORE_BCFKS="-Djavax.net.ssl.trustStoreType=bcfks"
JVM_OPTS="$JVM_OPTS_SECURITY_DEBUG $JVM_OPT_FIPS_MODE $JVM_OPT_TRUSTSTORE_BCFKS"

. ./cluster-config.sh
. ./common.sh
launch_security_test