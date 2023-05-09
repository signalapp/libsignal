//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class SignalRpcMessage {

  private String method;
  private String urlFragment;
  private byte[] body;
  private Map<String, List<String>> headers;

  public SignalRpcMessage() {
    this.headers = new HashMap<>();
  }

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public byte[] getBody() {
    return body;
  }

  public void setBody(byte[] body) {
    this.body = body;
  }

  public String getUrlFragment() {
    return urlFragment;
  }

  public void setUrlFragment(String urlFragment) {
    this.urlFragment = urlFragment;
  }

  public Map<String, List<String>> getHeaders() {
    return headers;
  }

  public void setHeaders(Map<String, List<String>> headers) {
    this.headers = headers;
  }

  public void header(String headerKey, String headerValue) {
    this.headers.computeIfAbsent(headerKey, key -> new LinkedList<>()).add(headerValue);
  }
}
