//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

public class TokioAsyncContextTest {
  @Test
  public void loadExceptionClasses() throws ExecutionException, InterruptedException {
    TokioAsyncContext context = new TokioAsyncContext();
    assertCanLoadClass(context, "org.signal.libsignal.net.CdsiProtocolException");
    assertCanLoadClass(context, "org.signal.libsignal.net.NetworkException");
  }

  @Test
  public void loadNonexistentClasses() throws ExecutionException, InterruptedException {
    TokioAsyncContext context = new TokioAsyncContext();
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist1");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist2");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist3");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist4");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist5");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist6");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist7");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist8");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist9");
    assertClassNotFound(context, "org.signal.libsignal.ClassThatDoesNotExist10");
  }

  /** Assert that the class with the given name can be loaded on a Tokio worker thread. */
  private static void assertCanLoadClass(TokioAsyncContext context, String className)
      throws ExecutionException, InterruptedException {
    Future<Class<Object>> loadAsync = context.loadClassAsync(className);
    // Block waiting for the future to resolve.
    Class<Object> loaded = loadAsync.get();
    assertEquals(className, loaded.getName());
  }

  /** Assert that the class doesn't exist. */
  private static void assertClassNotFound(TokioAsyncContext context, String className)
      throws ExecutionException, InterruptedException {
    Future<Class<Object>> loadAsync = context.loadClassAsync(className);
    // Block waiting for the future to resolve.
    Throwable cause =
        assertThrows(
                "for " + className,
                ExecutionException.class,
                () -> loadAsync.get(10, TimeUnit.SECONDS))
            .getCause();
    assertTrue(
        "unexpected error: " + cause,
        cause instanceof ClassNotFoundException || cause instanceof NoClassDefFoundError);
  }

  @Test
  public void runNetworkClassLoadTestFunction() throws ExecutionException, InterruptedException {
    Network.checkClassesCanBeLoadedAsyncForTest();
  }
}
