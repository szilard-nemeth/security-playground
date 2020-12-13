#!/usr/bin/env bash

#CLUSTER 1
CLUSTER1_HOST="snemeth-fips2-2.vpc.cloudera.com"
CLUSTER1_SSH_HOST="root@$CLUSTER1_HOST"
CLUSTER1_SSH_PARAMS=""
CLUSTER1_JAVA="/usr/java/jdk1.8.0_231/bin/java"

#CLUSTER 2
CLUSTER2_HOST="10.113.204.91"
CLUSTER2_SSH_HOST="centos@$CLUSTER2_HOST"
CLUSTER2_SSH_PARAMS="-i ~/cdp71-key.pem"
CLUSTER2_JAVA="/usr/lib/jvm/java-openjdk/bin/java"