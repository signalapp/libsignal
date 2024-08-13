//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import org.signal.libsignal.protocol.logging.Log;

/**
 * A collection of helper methods for limiting which checked exceptions can escape a block of code.
 *
 * <p>The specified exceptions, if any, will propagate normally, as will {@link Error}s and {@link
 * RuntimeException}s. Any other exceptions will be wrapped in {@link AssertionError} and their
 * unexpected-ness will be logged.
 *
 * <p>Intended for use with {@code native} methods, where exception specs aren't enforced.
 *
 * <pre>
 * PublicKey key = FilterExceptions.filterExceptions(
 *   InvalidKeyException.class,
 *   () -> Native.doSomethingThatMightFail(keyBytes));
 * </pre>
 */
public class FilterExceptions {
  /** A "functional interface" for an operation that returns an object and can throw. */
  @FunctionalInterface
  public interface ThrowingNativeOperation<R> {
    R run() throws Exception;
  }

  /** A "functional interface" for an operation that returns an {@code int} and can throw. */
  @FunctionalInterface
  public interface ThrowingNativeIntOperation {
    int run() throws Exception;
  }

  /** A "functional interface" for an operation that returns a {@code long} and can throw. */
  @FunctionalInterface
  public interface ThrowingNativeLongOperation {
    long run() throws Exception;
  }

  /** A "functional interface" for an operation that has no result but can throw. */
  @FunctionalInterface
  public interface ThrowingNativeVoidOperation {
    void run() throws Exception;
  }

  /**
   * A "functional interface" for an operation that maps a {@code long} value to an object and can
   * throw.
   */
  @FunctionalInterface
  public interface ThrowingLongFunction<R> {
    R apply(long value) throws Exception;
  }

  /**
   * A "functional interface" for an operation that accepts a {@code long} value, has no result, and
   * can throw.
   */
  @FunctionalInterface
  public interface ThrowingLongConsumer {
    void accept(long value) throws Exception;
  }

  private static AssertionError reportUnexpectedException(Exception e) {
    String message = "Unexpected checked exception " + e.getClass();
    Log.e("libsignal", message, e);
    return new AssertionError(message, e);
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  public static <R> R filterExceptions(ThrowingNativeOperation<R> f) {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  public static int filterExceptions(ThrowingNativeIntOperation f) {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  public static long filterExceptions(ThrowingNativeLongOperation f) {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  public static void filterExceptions(ThrowingNativeVoidOperation f) {
    try {
      f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E} in
   * {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <R, E extends Exception> R filterExceptions(
      Class<E> e1, ThrowingNativeOperation<R> f) throws E {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E} in
   * {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <E extends Exception> long filterExceptions(
      Class<E> e1, ThrowingNativeLongOperation f) throws E {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E} in
   * {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <E extends Exception> void filterExceptions(
      Class<E> e1, ThrowingNativeVoidOperation f) throws E {
    try {
      f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1} and
   * {@code E2} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <R, E1 extends Exception, E2 extends Exception> R filterExceptions(
      Class<E1> e1, Class<E2> e2, ThrowingNativeOperation<R> f) throws E1, E2 {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1} and
   * {@code E2} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <E1 extends Exception, E2 extends Exception> void filterExceptions(
      Class<E1> e1, Class<E2> e2, ThrowingNativeVoidOperation f) throws E1, E2 {
    try {
      f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1},
   * {@code E2}, and {@code E3} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <E1 extends Exception, E2 extends Exception, E3 extends Exception>
      long filterExceptions(Class<E1> e1, Class<E2> e2, Class<E3> e3, ThrowingNativeLongOperation f)
          throws E1, E2, E3 {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      if (e3.isInstance(e)) {
        throw (E3) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1},
   * {@code E2}, {@code E3}, and {@code E4} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <
          R, E1 extends Exception, E2 extends Exception, E3 extends Exception, E4 extends Exception>
      R filterExceptions(
          Class<E1> e1, Class<E2> e2, Class<E3> e3, Class<E4> e4, ThrowingNativeOperation<R> f)
          throws E1, E2, E3, E4 {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      if (e3.isInstance(e)) {
        throw (E3) e;
      }
      if (e4.isInstance(e)) {
        throw (E4) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1},
   * {@code E2}, {@code E3}, and {@code E4} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <
          E1 extends Exception, E2 extends Exception, E3 extends Exception, E4 extends Exception>
      long filterExceptions(
          Class<E1> e1, Class<E2> e2, Class<E3> e3, Class<E4> e4, ThrowingNativeLongOperation f)
          throws E1, E2, E3, E4 {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      if (e3.isInstance(e)) {
        throw (E3) e;
      }
      if (e4.isInstance(e)) {
        throw (E4) e;
      }
      throw reportUnexpectedException(e);
    }
  }

  /**
   * Tries to run {@code f}, wrapping all checked exceptions besides subclasses of {@code E1},
   * {@code E2}, {@code E3}, {@code E4}, and {@code E5} in {@link AssertionError}.
   *
   * <p>See the class-level documentation for more details.
   */
  @SuppressWarnings("unchecked")
  public static <
          R,
          E1 extends Exception,
          E2 extends Exception,
          E3 extends Exception,
          E4 extends Exception,
          E5 extends Exception>
      R filterExceptions(
          Class<E1> e1,
          Class<E2> e2,
          Class<E3> e3,
          Class<E4> e4,
          Class<E5> e5,
          ThrowingNativeOperation<R> f)
          throws E1, E2, E3, E4, E5 {
    try {
      return f.run();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Exception e) {
      if (e1.isInstance(e)) {
        throw (E1) e;
      }
      if (e2.isInstance(e)) {
        throw (E2) e;
      }
      if (e3.isInstance(e)) {
        throw (E3) e;
      }
      if (e4.isInstance(e)) {
        throw (E4) e;
      }
      if (e5.isInstance(e)) {
        throw (E5) e;
      }
      throw reportUnexpectedException(e);
    }
  }
}
