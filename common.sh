#!/usr/bin/env bash

#COMMON
JARNAME="security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar"

LOG_FILE="securitytest.log"
OUT_ERR_FILE="stdout_stderr"

#Result variables
RESULTS_WITHOUT_KS_PREFIX="results_without_keystore"
RESULTS_WITH_EMPTY_KS_PREFIX="results_with_empty_keystore"
TARGET_DIR="/tmp/securitytest_results"


function securitytest_keystore() {
    set -x
    
    local host="$1"
    local ssh_host="$2"
    local ssh_params="$3"
    local java_binary="$4"
    local md5_of_jar="$5"
    local jvm_opts="$6"
    local test_type="$7"

    if [ "$test_type" = "WITHOUT_KEYSTORE" ]; then
        local result_file_name="$RESULTS_WITHOUT_KS_PREFIX.tar"
    else
        local result_file_name="$RESULTS_WITH_EMPTY_KS_PREFIX.tar"
    fi

    local md5_of_jar_on_cluster=$(ssh ${ssh_params} ${ssh_host} "md5sum ~/$JARNAME | awk '{ print \$1 }'")

    if [ "$md5_of_jar_on_cluster" != "$md5_of_jar" ]; then
        echo "md5 sum of jar are different. Local: $md5_of_jar, Remote: $md5_of_jar_on_cluster"
        scp ${ssh_params} ./target/${JARNAME} ${ssh_host}:
    else
        echo "md5 sum of jar is the same on local and remote machine. Not copying the jar to the remote machine."
    fi


    mkdir -p "$TARGET_DIR/$host"
    echo "Removing log files"
    ssh ${ssh_params} ${ssh_host} "rm $LOG_FILE && rm $OUT_ERR_FILE"
    ssh ${ssh_params} ${ssh_host} "$java_binary -jar $jvm_opts $JARNAME $test_type > ./$OUT_ERR_FILE 2>&1"
    ssh ${ssh_params} ${ssh_host} "tar cvf $result_file_name $LOG_FILE $OUT_ERR_FILE"
    scp ${ssh_params} ${ssh_host}:${result_file_name} .
    mv ${result_file_name} "$TARGET_DIR/$host/$result_file_name"
    
    local tar_out_dir="$TARGET_DIR/$host/${result_file_name%.*}"
    mkdir -p ${tar_out_dir}
    tar -zxf "$TARGET_DIR/$host/$result_file_name" --directory "$tar_out_dir"

    set +x
}

function launch_security_test() {
    rm -rf ${TARGET_DIR}
    
    #BUILD TEST JAR
    mvn clean install
    MD5_OF_JAR=$(md5 -q ./target/${JARNAME})
    
    ## CLUSTER1
    securitytest_keystore $CLUSTER1_HOST "$CLUSTER1_SSH_HOST" "$CLUSTER1_SSH_PARAMS" $CLUSTER1_JAVA $MD5_OF_JAR "$JVM_OPTS" "WITHOUT_KEYSTORE"
    securitytest_keystore $CLUSTER1_HOST "$CLUSTER1_SSH_HOST" "$CLUSTER1_SSH_PARAMS" $CLUSTER1_JAVA $MD5_OF_JAR "$JVM_OPTS" "WITH_EMPTY_KEYSTORE"
    
    ## CLUSTER2
    securitytest_keystore $CLUSTER2_HOST "$CLUSTER2_SSH_HOST" "$CLUSTER2_SSH_PARAMS" $CLUSTER2_JAVA $MD5_OF_JAR "$JVM_OPTS" "WITHOUT_KEYSTORE"
    securitytest_keystore $CLUSTER2_HOST "$CLUSTER2_SSH_HOST" "$CLUSTER2_SSH_PARAMS" $CLUSTER2_JAVA $MD5_OF_JAR "$JVM_OPTS" "WITH_EMPTY_KEYSTORE"
    
    echo "FINISHED"
    echo "Result files are here: $TARGET_DIR"
}