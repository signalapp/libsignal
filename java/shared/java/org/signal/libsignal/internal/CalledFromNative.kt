//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

import java.lang.reflect.Constructor
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import kotlin.annotation.AnnotationTarget
import kotlin.annotation.MustBeDocumented
import kotlin.annotation.Target

/**
 * Declares that a class or field is accessed via JNI.
 *
 * This should be used to annotate classes, methods, and fields that are accessed by Rust code
 * via JNI. Methods and fields with this annotation will not be renamed or stripped during dead code
 * analysis. Classes with this annotation will not be stripped (though their methods may be renamed
 * or stripped unless annotated).
 */
@MustBeDocumented
@Target(AnnotationTarget.CONSTRUCTOR, AnnotationTarget.FIELD, AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
public annotation class CalledFromNative {
  public class Enforcement {
    public companion object {
      /**
       * Checks that the constructor for the given class that takes the given
       * arguments is annotated to avoid being stripped.
       *
       * @throws AssertionError if the constructor isn't annotated.
       */
      @JvmStatic
      @Throws(AssertionError::class)
      public fun checkConstructor(constructor: Constructor<*>) {
        val stringifiedArgs: String by lazy { constructor.parameterTypes.joinToString(", ") { it?.name ?: "null" } }

        var declaringClass = constructor.declaringClass

        // Now that we've found the constructor being invoked, make sure it's
        // going to be preserved by the dead code stripper. These checks are a
        // conservative subset of the retention rules in `libsignal.pro`.

        // Special-case everything in the java package; it's not bundled and
        // so can't be stripped.
        if (declaringClass.getPackage()?.name?.startsWith("java.") == true) {
          return
        }

        // Special-case kotlin.Pair; we mention its constructor manually in libsignal.pro.
        if (declaringClass == Pair::class.java) {
          return
        }

        // If the constructor itself is annotated directly, we're done.
        if (constructor.isAnnotationPresent(CalledFromNative::class.java)) {
          return
        }

        // Special-case constructors of libsignal exception types. These are
        // kept even without annotations!
        if (declaringClass.getPackage()?.name?.startsWith("org.signal.libsignal") == true &&
          Exception::class.java.isAssignableFrom(declaringClass)
        ) {
          return
        }

        throw AssertionError("Constructor $declaringClass($stringifiedArgs) is not annotated")
      }

      /**
       * Checks that the called method on the given target is annotated to avoid being stripped.
       *
       * @throws AssertionError if the method isn't annotated.
       */
      @JvmStatic
      @Throws(AssertionError::class)
      public fun checkCalledMethod(method: Method) {
        var declaringClass = method.declaringClass
        val stringifiedArgs: String by lazy { method.parameterTypes.joinToString(", ") { it?.name ?: "null" } }
        // Now that we've found the method to call, make sure it's going to be
        // preserved by the dead code stripper. These checks correspond to the
        // retention rules in `libsignal.pro`.

        // Special-case everything in the java package; it's not bundled and
        // so can't be stripped.
        if (declaringClass.getPackage()?.name?.startsWith("java.") == true) {
          return
        }

        // If the method itself is annotated directly, we're done.
        if (method.isAnnotationPresent(CalledFromNative::class.java)) {
          return
        }

        // We also allow invoking interface methods where only the interface is
        // annotated. Check whether the found method is declared by an interface
        // implemented by this class or any of its ancestors.
        for (k in generateSequence(declaringClass) { it.superclass }) {
          for (m in findMethodOnImplementedInterfaces(k, method.name, method.parameterTypes)) {
            if (m.declaringClass.isAnnotationPresent(CalledFromNative::class.java)) {
              return
            }
          }
        }

        throw AssertionError("Instance method ${declaringClass.name}.${method.name}($stringifiedArgs) is not annotated")
      }

      /**
       * Checks that the called static method on the given target is annotated to avoid being stripped.
       *
       * @throws AssertionError if the method isn't annotated.
       */
      @JvmStatic
      @Throws(AssertionError::class)
      public fun checkCalledStaticMethod(method: Method) {
        val stringifiedArgs: String by lazy { method.parameterTypes.joinToString(", ") { it?.name ?: "null" } }

        var declaringClass = method.declaringClass

        if (!Modifier.isStatic(method.modifiers)) {
          throw AssertionError("method ${declaringClass.name}.${method.name}($stringifiedArgs) is not static")
        }

        // Now that we've found the method to call, make sure it's going to be
        // preserved by the dead code stripper. These checks correspond to the
        // retention rules in `libsignal.pro`.

        // Special-case everything in the java package; it's not bundled and
        // so can't be stripped.
        if (declaringClass.getPackage()?.name?.startsWith("java.") == true) {
          return
        }

        // If the method itself is annotated directly, we're done.
        if (method.isAnnotationPresent(CalledFromNative::class.java)) {
          return
        }

        throw AssertionError("Static method ${declaringClass.name}.${method.name}($stringifiedArgs) is not annotated")
      }

      private fun findMethodOnImplementedInterfaces(
        klass: Class<*>,
        methodName: String,
        argumentTypes: Array<Class<*>>,
      ) = sequence {
        var interfaces =
          klass.let {
            var stack = arrayListOf(it)
            var found = HashSet<Class<*>>()

            while (true) {
              var first = stack.removeLastOrNull() ?: break
              found.add(first)
              first.interfaces.filterNotTo(stack) { found.contains(it) }
            }
            found
          }
        for (inter in interfaces) {
          try {
            yield(inter.getDeclaredMethod(methodName, *argumentTypes))
          } catch (e: NoSuchMethodException) {
          }
        }
      }
    }
  }
}
