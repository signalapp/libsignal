//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.TokioAsyncContext
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

internal data class GrpcTestCase<Req, Resp>
  @CalledFromNative
  constructor(
    val name: String,
    val method: String,
    val request: Req,
    val requestGrpc: ByteArray,
    val responseGrpc: ByteArray,
    val response: Resp,
  ) {
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

      internal fun <Req, Resp, Service, T> runTests(
        tests: List<GrpcTestCase<Req, Resp>>,
        newService: (AuthenticatedChatConnection) -> Service,
        invoke: (Service, Req) -> CompletableFuture<T>,
        check: (Resp, T) -> Unit,
      ) {
        for (test in tests) {
          val tokioAsyncContext = TokioAsyncContext()
          val (chat, fakeRemote) =
            AuthenticatedChatConnection.fakeConnect(
              tokioAsyncContext,
              NoOpListener(),
            )
          val responseFuture = invoke(newService(chat), test.request)
          val (request, requestId) = fakeRemote.getNextIncomingGrpcRequest().get(5, TimeUnit.SECONDS)
          assertEquals(request.pathAndQuery, test.method)
          val (start, end) =
            NativeTesting.TESTING_FakeChatRemoteEnd_NextGrpcMessage(
              request.body,
              0,
            )
          assertEquals(end, request.body.size)
          assertContentEquals(test.requestGrpc, request.body.sliceArray(start..<request.body.size))
          fakeRemote.sendGrpcResponse(requestId, test.responseGrpc)
          check(test.response, responseFuture.get(5, TimeUnit.SECONDS))
        }
      }
    }
  }

internal inline fun <T, E : BadRequestError, reified SubError : E> RequestResult<T, E>.assertNonSuccess(): SubError =
  assertIs<SubError>(assertIs<RequestResult.NonSuccess<E>>(this).error)
