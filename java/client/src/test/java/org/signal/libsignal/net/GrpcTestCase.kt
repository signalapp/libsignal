//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.ObjectHandle
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.internal.await
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

public class GrpcTestCaseResponse(
  nativeHandle: ObjectHandle,
) : NativeHandleGuard.SimpleOwner(nativeHandle) {
  override fun release(nativeHandle: ObjectHandle) {
    NativeTesting.GrpcTestCaseBridgedResponse_Destroy(nativeHandle)
  }
}

public class GrpcTestCase<Req, Resp> {
  val name: String
  val method: String
  val request: Req
  val requestGrpc: ByteArray
  val responseGrpc: GrpcTestCaseResponse
  val response: Resp

  private constructor(
    name: String,
    method: String,
    request: Req,
    requestGrpc: ByteArray,
    responseGrpc: GrpcTestCaseResponse,
    response: Resp,
  ) {
    this.name = name
    this.method = method
    this.request = request
    this.requestGrpc = requestGrpc
    this.responseGrpc = responseGrpc
    this.response = response
  }

  @CalledFromNative
  constructor(
    name: String,
    method: String,
    request: Req,
    requestGrpc: ByteArray,
    responseGrpc: ObjectHandle,
    response: Resp,
  ) :
    this(name, method, request, requestGrpc, GrpcTestCaseResponse(responseGrpc), response) {}

  companion object {
    @Suppress("UNCHECKED_CAST")
    internal inline fun <reified Req, reified Resp, Req2, Resp2> resultConverter(
      crossinline mapRequest: (Req) -> Req2,
      crossinline mapResponse: (Resp) -> Resp2,
    ): (Array<Object>) -> List<GrpcTestCase<Req2, Resp2>> =
      {
        it.asList().map {
          val casted = it as GrpcTestCase<Any?, Any?>
          GrpcTestCase(
            name = casted.name,
            method = casted.method,
            request = mapRequest(casted.request as Req),
            requestGrpc = casted.requestGrpc,
            responseGrpc = casted.responseGrpc,
            response = mapResponse(casted.response as Resp),
          )
        }
      }

    internal suspend fun <Req, Resp, Conn, Service, T> runTests(
      tests: List<GrpcTestCase<Req, Resp>>,
      newConnection: (TokioAsyncContext, NoOpListener) -> Pair<Conn, FakeChatRemote>,
      newService: (Conn) -> Service,
      invoke: (Service, Req) -> CompletableFuture<T>,
      check: (Resp, T) -> Unit,
    ) =
      this.runSuspendingTests(tests, newConnection, newService, { service, req -> invoke(service, req).await() }, check)

    internal suspend fun <Req, Resp, Conn, Service, T> runSuspendingTests(
      tests: List<GrpcTestCase<Req, Resp>>,
      newConnection: (TokioAsyncContext, NoOpListener) -> Pair<Conn, FakeChatRemote>,
      newService: (Conn) -> Service,
      invoke: suspend (Service, Req) -> T,
      check: (Resp, T) -> Unit,
    ) {
      for (test in tests) {
        coroutineScope {
          val tokioAsyncContext = TokioAsyncContext()
          val (chat, fakeRemote) = newConnection(tokioAsyncContext, NoOpListener())
          val deferredResponse =
            async {
              invoke(newService(chat), test.request)
            }
          val (request, requestId) =
            withContext(Dispatchers.Default.limitedParallelism(1)) {
              withTimeout(5.seconds) {
                fakeRemote.getNextIncomingGrpcRequest().await()
              }
            }
          assertEquals(request.pathAndQuery, test.method)
          val (start, end) =
            NativeTesting.TESTING_FakeChatRemoteEnd_NextGrpcMessage(
              request.body,
              0,
            )
          assertEquals(end, request.body.size)
          assertContentEquals(test.requestGrpc, request.body.sliceArray(start..<request.body.size))
          fakeRemote.sendGrpcResponse(requestId, test.responseGrpc)
          val response =
            withContext(
              Dispatchers.Default.limitedParallelism(1),
            ) { withTimeout(5.seconds) { deferredResponse.await() } }
          check(test.response, response)
        }
      }
    }
  }
}

private fun FakeChatRemote.sendGrpcResponse(
  requestId: Long,
  fullResponse: GrpcTestCaseResponse,
): CompletableFuture<Void?> =
  tokioContext.guardedMap { asyncContextHandle ->
    guardedMap { fakeRemote ->
      fullResponse.guardedMap { response ->
        NativeTesting.TESTING_FakeChatRemoteEnd_SendServerGrpcTestCaseResponse(
          asyncContextHandle,
          fakeRemote,
          requestId,
          response,
        )
      }
    }
  }

internal inline fun <T, E : BadRequestError, reified SubError : E> RequestResult<T, E>.assertNonSuccess(): SubError =
  assertIs<SubError>(assertIs<RequestResult.NonSuccess<E>>(this).error)
