# Commands to run

## Build on local machine

```
mvn clean install
```

## Launch with log4j debug
```
java -Dlog4j.debug -jar $HOME/.m2/repository/com/szilardnemeth/security/security-playground/1.0-SNAPSHOT/security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar WITH_EMPTY_KEYSTORE
```

## Launch normally - Without keystore
```
java -jar $HOME/.m2/repository/com/szilardnemeth/security/security-playground/1.0-SNAPSHOT/security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar WITHOUT_KEYSTORE
```

## Launch normally - With empty keystore
```
java -jar $HOME/.m2/repository/com/szilardnemeth/security/security-playground/1.0-SNAPSHOT/security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar WITH_EMPTY_KEYSTORE
```



## Launch with security debug JVM options - Without keystore
```
java -jar -Djava.security.debug=all -Djavax.net.debug=all -Dcom.safelogic.cryptocomply.fips.approved_only=true $HOME/.m2/repository/com/szilardnemeth/security/security-playground/1.0-SNAPSHOT/security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar WITHOUT_KEYSTORE
```

## Launch with security debug JVM options - With empty keystore
```
java -jar -Djava.security.debug=all -Djavax.net.debug=all -Dcom.safelogic.cryptocomply.fips.approved_only=true $HOME/.m2/repository/com/szilardnemeth/security/security-playground/1.0-SNAPSHOT/security-playground-1.0-SNAPSHOT-jar-with-dependencies.jar WITH_EMPTY_KEYSTORE
```
