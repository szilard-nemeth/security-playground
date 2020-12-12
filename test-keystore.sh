#!/usr/bin/env bash


#COMMON
JARNAME="security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar"
JVM_OPTS_SECURITY_DEBUG="-Djava.security.debug=all -Djavax.net.debug=all"
JVM_OPT_FIPS_MODE="-Dcom.safelogic.cryptocomply.fips.approved_only=true"

LOG_FILE="securitytest.log"
OUT_ERR_FILE="stdout_stderr"

#Result variables
RESULTS_WITHOUT_KS_PREFIX="results_without_keystore"
RESULTS_WITH_EMPTY_KS_PREFIX="results_with_empty_keystore"
TARGET_DIR="/tmp/securitytest_results"


function test() {
    set -x
    
#    echo "1: $1"
#    echo "2: $2"
#    echo "3: $3"
#    echo "4: $4"
#    echo "5: $5"
#    echo "6: $6"
#    echo "7: $7"
#    echo "8: $8"
    
    local host="$1"
    local ssh_host="$2"
    local ssh_params="$3"
    local java_binary="$4"
    local test_type="$5"

    if [ "$test_type" = "WITHOUT_KEYSTORE" ]; then
        local result_file_name="$RESULTS_WITHOUT_KS_PREFIX.tar"
    else
        local result_file_name="$RESULTS_WITH_EMPTY_KS_PREFIX.tar"
    fi

    local md5_of_jar_on_cluster=$(ssh ${ssh_params} ${ssh_host} "md5sum ~/$JARNAME | awk '{ print \$1 }'")

    if [ "$md5_of_jar_on_cluster" != "$MD5_OF_JAR" ]; then
        echo "md5 sum of jar are different. Local: $MD5_OF_JAR, Remote: $md5_of_jar_on_cluster"
        scp ${ssh_params} ./target/${JARNAME} ${ssh_host}:
    else
        echo "md5 sum of jar is the same on local and remote machine. Not copying the jar to the remote machine."
    fi


    mkdir -p "$TARGET_DIR/$host"
    echo "Removing log files"
    ssh ${ssh_params} ${ssh_host} "rm $LOG_FILE && rm $OUT_ERR_FILE"
    ssh ${ssh_params} ${ssh_host} "$java_binary -jar $JVM_OPTS_SECURITY_DEBUG $JVM_OPT_FIPS_MODE $JARNAME $test_type > ./$OUT_ERR_FILE 2>&1"
    ssh ${ssh_params} ${ssh_host} "tar cvf $result_file_name $LOG_FILE $OUT_ERR_FILE"
    scp ${ssh_params} ${ssh_host}:${result_file_name} .
    mv ${result_file_name} "$TARGET_DIR/$host/$result_file_name"
    
    local tar_out_dir="$TARGET_DIR/$host/${result_file_name%.*}"
    mkdir -p ${tar_out_dir}
    tar -zxf "$TARGET_DIR/$host/$result_file_name" --directory "$tar_out_dir"

    set +x
}


#CLUSTER 1
CLUSTER1_HOST="snemeth-fips2-2.vpc.cloudera.com"
CLUSTER1_SSH_HOST="root@$CLUSTER1_HOST"
CLUSTER1_SSH_PARAMS=""
CLUSTER1_JAVA="/usr/java/jdk1.8.0_231/bin/java"

#CLUSTER 2
#declare -a CLUSTER2_SSH=("-i" "~/cdp71-key.pem" "$CLUSTER2_HOST")
#declare -a CLUSTER2_SCP=("-i" "~/cdp71-key.pem" "$CLUSTER2_HOST")
CLUSTER2_HOST="10.113.204.91"
CLUSTER2_SSH_HOST="centos@$CLUSTER2_HOST"
CLUSTER2_SSH_PARAMS="-i ~/cdp71-key.pem"
CLUSTER2_JAVA="/usr/lib/jvm/java-openjdk/bin/java"
######################################################

rm -rf $TARGET_DIR

#BUILD TEST JAR
mvn clean install
MD5_OF_JAR=$(md5 -q ./target/${JARNAME})

## CLUSTER1
test $CLUSTER1_HOST "$CLUSTER1_SSH_HOST" "$CLUSTER1_SSH_PARAMS" $CLUSTER1_JAVA "WITHOUT_KEYSTORE"
test $CLUSTER1_HOST "$CLUSTER1_SSH_HOST" "$CLUSTER1_SSH_PARAMS" $CLUSTER1_JAVA "WITH_EMPTY_KEYSTORE"

## CLUSTER2
test $CLUSTER2_HOST "$CLUSTER2_SSH_HOST" "$CLUSTER2_SSH_PARAMS" $CLUSTER2_JAVA "WITHOUT_KEYSTORE"
test $CLUSTER2_HOST "$CLUSTER2_SSH_HOST" "$CLUSTER2_SSH_PARAMS" $CLUSTER2_JAVA "WITH_EMPTY_KEYSTORE"


echo "FINISHED"
echo "Result files are here: $TARGET_DIR"