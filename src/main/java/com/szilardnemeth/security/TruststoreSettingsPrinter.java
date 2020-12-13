package com.szilardnemeth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.action.GetPropertyAction;

import java.io.File;
import java.security.KeyStore;

public class TruststoreSettingsPrinter {
  private static final Logger LOG = LoggerFactory.getLogger(TruststoreSettingsPrinter.class);

  private static final String fileSep = File.separator;
  private static final String defaultStorePath =
      GetPropertyAction.privilegedGetProperty("java.home") +
          fileSep + "lib" + fileSep + "security";
  private static final String defaultStore =
      defaultStorePath + fileSep + "cacerts";
  private static final String jsseDefaultStore =
      defaultStorePath + fileSep + "jssecacerts";


  public static void print() {
    LOG.info("Default store path: {}", defaultStorePath);
    LOG.info("Default store: {}", defaultStore);
    LOG.info("JSSE Default store: {}", jsseDefaultStore);
    LOG.info("Keystore.getDefaultType: {}", KeyStore.getDefaultType());
    
    
    String storePropName = System.getProperty("javax.net.ssl.trustStore", jsseDefaultStore);
    LOG.info("javax.net.ssl.trustStore: {}", System.getProperty("javax.net.ssl.trustStore"));
    LOG.info("javax.net.ssl.trustStore [storePropName]: {}", storePropName);

    String storePropType = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
    LOG.info("javax.net.ssl.trustStoreType: {}", System.getProperty("javax.net.ssl.trustStoreType"));
    LOG.info("javax.net.ssl.trustStoreType [storePropType]: {}", storePropType);

    String storePropProvider = System.getProperty("javax.net.ssl.trustStoreProvider", "");
    LOG.info("javax.net.ssl.trustStoreProvider: {}", System.getProperty("javax.net.ssl.trustStoreProvider"));
    LOG.info("javax.net.ssl.trustStoreProvider [storePropProvider]: {}", storePropProvider);


    String storePropPassword = System.getProperty("javax.net.ssl.trustStorePassword", "");
    LOG.info("javax.net.ssl.trustStorePassword: {}", System.getProperty("javax.net.ssl.trustStorePassword"));
    LOG.info("javax.net.ssl.trustStorePassword [storePropPassword]: {}", storePropPassword);

  }
}
