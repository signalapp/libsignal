//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import org.junit.Test;

public class CalledFromNativeTest {
  static class WithConstructors {
    @CalledFromNative
    WithConstructors() {}

    WithConstructors(Void v) {}
  }

  @Test
  public void testCheckConstructor() throws NoSuchMethodException {

    CalledFromNative.Enforcement.checkConstructor(WithConstructors.class.getDeclaredConstructor());
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkConstructor(
                WithConstructors.class.getDeclaredConstructor(Void.class)));
  }

  @Test
  public void testCheckNestedClassConstructor() throws NoSuchMethodException {
    class NestedClass {
      @CalledFromNative
      NestedClass() {}

      NestedClass(Void v) {}
    }

    CalledFromNative.Enforcement.checkConstructor(
        NestedClass.class.getDeclaredConstructor(CalledFromNativeTest.class));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkConstructor(
                NestedClass.class.getDeclaredConstructor(CalledFromNativeTest.class, Void.class)));
  }

  static class UnannotatedException extends Exception {
    UnannotatedException() {}
  }

  @Test
  public void testCheckExceptionConstructorExemption() throws NoSuchMethodException {
    CalledFromNative.Enforcement.checkConstructor(
        UnannotatedException.class.getDeclaredConstructor());
  }

  @Test
  public void testCheckCallInstanceMethod() throws NoSuchMethodException {
    class WithMethod {
      public void unannotated() {}

      @CalledFromNative
      public void annotated() {}
    }
    CalledFromNative.Enforcement.checkCalledMethod(WithMethod.class.getMethod("annotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                WithMethod.class.getMethod("unannotated")));
  }

  @Test
  public void testCheckCallWithPrimitiveArguments() throws NoSuchMethodException {
    class WithMethod {
      public void unannotated(int a, boolean b) {}

      @CalledFromNative
      public void annotated(int a, boolean b) {}
    }
    CalledFromNative.Enforcement.checkCalledMethod(
        WithMethod.class.getMethod("annotated", int.class, boolean.class));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                WithMethod.class.getMethod("unannotated", int.class, boolean.class)));
  }

  @Test
  public void testCheckCallWithSubclassArguments() throws NoSuchMethodException {
    class WithMethod {
      public void unannotated(Object o) {}

      @CalledFromNative
      public void annotated(Object o) {}
    }
    CalledFromNative.Enforcement.checkCalledMethod(
        WithMethod.class.getMethod("annotated", Object.class));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                WithMethod.class.getMethod("unannotated", Object.class)));
  }

  @Test
  public void testCheckCallAncestorClassMethod() throws NoSuchMethodException {
    class SuperclassWithMethod {
      public void unannotated() {}

      @CalledFromNative
      public void annotated() {}
    }

    class DirectSubclass extends SuperclassWithMethod {}

    class IndirectSubclass extends DirectSubclass {}

    CalledFromNative.Enforcement.checkCalledMethod(IndirectSubclass.class.getMethod("annotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                IndirectSubclass.class.getMethod("unannotated")));
  }

  @Test
  public void testCheckCallMethodFromAnnotatedInterface() throws NoSuchMethodException {
    @CalledFromNative
    interface AnnotatedInterface {
      public void onAnnotated();
    }
    interface UnannotatedInterface {
      public void onUnannotated();
    }

    class ImplementsInterfaces implements AnnotatedInterface, UnannotatedInterface {
      public void onAnnotated() {}

      public void onUnannotated() {}
    }

    CalledFromNative.Enforcement.checkCalledMethod(
        ImplementsInterfaces.class.getMethod("onAnnotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                ImplementsInterfaces.class.getMethod("onUnannotated")));
  }

  @Test
  public void testCheckCallMethodFromExtendedAnnotatedInterface() throws NoSuchMethodException {
    @CalledFromNative
    interface AnnotatedInterface {
      public void onAnnotated();
    }
    interface UnannotatedInterface {
      public void onUnannotated();
    }
    interface SuperInterface extends AnnotatedInterface, UnannotatedInterface {}

    class ImplementsInterfaces implements SuperInterface {
      public void onAnnotated() {}

      public void onUnannotated() {}
    }

    CalledFromNative.Enforcement.checkCalledMethod(
        ImplementsInterfaces.class.getMethod("onAnnotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                ImplementsInterfaces.class.getMethod("onUnannotated")));
  }

  @Test
  public void testCheckCallOverriddenMethodOnSubclassOfInterfaceImplementer()
      throws NoSuchMethodException {
    @CalledFromNative
    interface AnnotatedInterface {
      public void onAnnotated();
    }
    interface UnannotatedInterface {
      public void onUnannotated();
    }

    class ImplementsInterfaces implements AnnotatedInterface, UnannotatedInterface {
      public void onAnnotated() {}

      public void onUnannotated() {}
    }

    class OverridingSubclass extends ImplementsInterfaces {
      public void onAnnotated() {
        super.onUnannotated();
      }

      public void onUnannotated() {
        super.onUnannotated();
      }
    }

    CalledFromNative.Enforcement.checkCalledMethod(
        OverridingSubclass.class.getMethod("onAnnotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledMethod(
                OverridingSubclass.class.getMethod("onUnannotated")));
  }

  @Test
  public void testMethodOnAnnotatedEnum() throws NoSuchMethodException {
    @CalledFromNative
    enum AnnotatedEnum {
      ONE,
      TWO;
    }
    enum UnannotatedEnum {
      THREE,
      FOUR;
    }
    // java.lang.Enum.ordinal is always available, even on unannotated enum types.
    CalledFromNative.Enforcement.checkCalledMethod(AnnotatedEnum.class.getMethod("ordinal"));
    CalledFromNative.Enforcement.checkCalledMethod(UnannotatedEnum.class.getMethod("ordinal"));
  }

  @Test
  public void testCallStaticMethodDirect() throws NoSuchMethodException {
    class WithStaticMethods {
      @CalledFromNative
      public static void annotated() {}

      public static void unannotated() {}
    }

    CalledFromNative.Enforcement.checkCalledStaticMethod(
        WithStaticMethods.class.getMethod("annotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledStaticMethod(
                WithStaticMethods.class.getMethod("unannotated")));
  }

  @Test
  public void testCallStaticMethodOnSuperclass() throws NoSuchMethodException {
    class WithStaticMethods {
      @CalledFromNative
      public static void annotated() {}

      public static void unannotated() {}
    }

    class Subclass extends WithStaticMethods {}

    CalledFromNative.Enforcement.checkCalledStaticMethod(Subclass.class.getMethod("annotated"));
    assertThrows(
        AssertionError.class,
        () ->
            CalledFromNative.Enforcement.checkCalledStaticMethod(
                Subclass.class.getMethod("unannotated")));
  }
}
