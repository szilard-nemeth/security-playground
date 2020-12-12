/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.szilardnemeth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * Utility class that contains commonly used server methods.
 *
 */
public final class SecurityUtils {
  private static final Logger LOG =
      LoggerFactory.getLogger(SecurityUtils.class);

  public static final String CCJ_FIPS_APPROVED_ONLY_PROPERTY =
      "com.safelogic.cryptocomply.fips.approved_only";
  public static final String DEFAULT_KEYSTORE_TYPE = "JKS";
  public static final String KEYSTORE_TYPE_BCFKS = "BCFKS";

  private SecurityUtils() {
  }

  
  
  public static boolean isFipsEnabled() {
    String fipsApprovedModeValue = System.getProperty(
        CCJ_FIPS_APPROVED_ONLY_PROPERTY);
    final boolean fipsEnabled = fipsApprovedModeValue != null &&
        Boolean.valueOf(fipsApprovedModeValue);
    
    if (LOG.isTraceEnabled()) {
      LOG.trace("FIPS mode: {}, value of JVM property '{}' is: {}",
          fipsEnabled, CCJ_FIPS_APPROVED_ONLY_PROPERTY, fipsApprovedModeValue);
    }
    return fipsEnabled;
  }

  public static void printSecurityProviders() {
    if (LOG.isTraceEnabled()) {
      LOG.trace("Available Security Providers are:");
    }
    
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      Provider provider = providers[i];
      if (LOG.isTraceEnabled()) {
        LOG.trace("[" + (i + 1) + "] - Name: " + provider.getName());
        LOG.trace("Information:\n" + provider.getInfo());
        LOG.trace("Listing providers with types of service " +
            "and algorithm provided:\n");
      }

      Set<Provider.Service> services = provider.getServices();
      List<Provider.Service> servicesList = new ArrayList<>(services);
      servicesList.sort(Comparator.comparing(Provider.Service::getType));
      for (Provider.Service service : servicesList) {
        if (LOG.isTraceEnabled()) {
          LOG.trace(String.format("- Name: %s, Service Type: %s, Algorithm: %s",
              provider.getName(), service.getType(), service.getAlgorithm()));
        }
      }
    }
  }

  /**
   * Return the index af the given Security Provider.
   * Note that the index is 1-based.
   * @param providerName
   * @return The index, or -1 if the provider is null or was not found.
   */
  public static int getProviderIndex(String providerName) {
    int providerIndex = 1;
    if (providerName == null) {
      return -1;
    }
    for (Provider provider : Security.getProviders()) {
      if (providerName.equalsIgnoreCase(provider.getName())) {
        return providerIndex;
      }
      providerIndex++;
    }
    return -1;
  }
}
