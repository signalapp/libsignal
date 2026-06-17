package org.signal.libsignal.internal

import org.signal.libsignal.internal.FilterExceptions.reportUnexpectedException

internal inline fun <U> filterAllExceptions(crossinline thunk: () -> U): U =
  try {
    thunk()
  } catch (e: java.lang.Error) {
    throw e
  } catch (e: Exception) {
    when (e) {
      is RuntimeException -> throw e
      else ->
        throw reportUnexpectedException(e)
    }
  }

internal inline fun <reified T, U> filterExceptions(crossinline thunk: () -> U): U =
  try {
    thunk()
  } catch (e: java.lang.Error) {
    throw e
  } catch (e: Exception) {
    when (e) {
      is T, is RuntimeException -> throw e
      else ->
        throw reportUnexpectedException(e)
    }
  }
