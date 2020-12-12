package com.szilardnemeth.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Main {
  public static void main(String[] args) throws GeneralSecurityException, IOException {
    if (args.length != 1) {
      throw new RuntimeException("Expected argument: Mode of TrustManager init. Values should be one of: " + Arrays.toString(TrustManagerFactoryInitMode.values()));
    }

    String initModeStr = args[0];
    TrustManagerFactoryInitMode initMode =
        TrustManagerFactoryInitMode.valueOf(initModeStr);

    SecurityTest securityTest = new SecurityTest(initMode);
    securityTest.init();
  }
}
