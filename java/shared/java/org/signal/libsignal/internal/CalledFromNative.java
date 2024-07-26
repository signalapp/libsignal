//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * Declares that a class or field is accessed via JNI.
 *
 * <p>This should be used to annotate classes, methods, and fields that are accessed by Rust code
 * via JNI. Methods and fields with this annotation will not be renamed or stripped during dead code
 * analysis. Classes with this annotation will not be stripped (though their methods may be renamed
 * or stripped unless annotated).
 */
@Documented
@Target({ElementType.CONSTRUCTOR, ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
public @interface CalledFromNative {}
