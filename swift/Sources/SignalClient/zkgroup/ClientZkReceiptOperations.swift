//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//
// Generated by zkgroup/codegen/codegen.py - do not edit

import Foundation
import SignalFfi

public class ClientZkReceiptOperations {

  let serverPublicParams: ServerPublicParams

  public init(serverPublicParams: ServerPublicParams) {
    self.serverPublicParams = serverPublicParams
  }

  public func createReceiptCredentialRequestContext(receiptSerial: ReceiptSerial) throws  -> ReceiptCredentialRequestContext {
    var randomness: [UInt8] = Array(repeating: 0, count: Int(32))
    let result = SecRandomCopyBytes(kSecRandomDefault, randomness.count, &randomness)
    guard result == errSecSuccess else {
      throw ZkGroupException.AssertionError
    }

    return try createReceiptCredentialRequestContext(randomness: randomness, receiptSerial: receiptSerial)
  }

  public func createReceiptCredentialRequestContext(randomness: [UInt8], receiptSerial: ReceiptSerial) throws  -> ReceiptCredentialRequestContext {
    var newContents: [UInt8] = Array(repeating: 0, count: ReceiptCredentialRequestContext.SIZE)

    let ffi_return = FFI_ServerPublicParams_createReceiptCredentialRequestContextDeterministic(serverPublicParams.getInternalContentsForFFI(), UInt32(serverPublicParams.getInternalContentsForFFI().count), randomness, UInt32(randomness.count), receiptSerial.getInternalContentsForFFI(), UInt32(receiptSerial.getInternalContentsForFFI().count), &newContents, UInt32(newContents.count))
    if (ffi_return == Native.FFI_RETURN_INPUT_ERROR) {
      throw ZkGroupException.VerificationFailed
    }

    if (ffi_return != Native.FFI_RETURN_OK) {
      throw ZkGroupException.ZkGroupError
    }

    do {
      return try ReceiptCredentialRequestContext(contents: newContents)
    } catch ZkGroupException.InvalidInput {
      throw ZkGroupException.AssertionError
    }

  }

  public func receiveReceiptCredential(receiptCredentialRequestContext: ReceiptCredentialRequestContext, receiptCredentialResponse: ReceiptCredentialResponse) throws  -> ReceiptCredential {
    var newContents: [UInt8] = Array(repeating: 0, count: ReceiptCredential.SIZE)

    let ffi_return = FFI_ServerPublicParams_receiveReceiptCredential(serverPublicParams.getInternalContentsForFFI(), UInt32(serverPublicParams.getInternalContentsForFFI().count), receiptCredentialRequestContext.getInternalContentsForFFI(), UInt32(receiptCredentialRequestContext.getInternalContentsForFFI().count), receiptCredentialResponse.getInternalContentsForFFI(), UInt32(receiptCredentialResponse.getInternalContentsForFFI().count), &newContents, UInt32(newContents.count))
    if (ffi_return == Native.FFI_RETURN_INPUT_ERROR) {
      throw ZkGroupException.VerificationFailed
    }

    if (ffi_return != Native.FFI_RETURN_OK) {
      throw ZkGroupException.ZkGroupError
    }

    do {
      return try ReceiptCredential(contents: newContents)
    } catch ZkGroupException.InvalidInput {
      throw ZkGroupException.AssertionError
    }

  }

  public func createReceiptCredentialPresentation(receiptCredential: ReceiptCredential) throws  -> ReceiptCredentialPresentation {
    var randomness: [UInt8] = Array(repeating: 0, count: Int(32))
    let result = SecRandomCopyBytes(kSecRandomDefault, randomness.count, &randomness)
    guard result == errSecSuccess else {
      throw ZkGroupException.AssertionError
    }

    return try createReceiptCredentialPresentation(randomness: randomness, receiptCredential: receiptCredential)
  }

  public func createReceiptCredentialPresentation(randomness: [UInt8], receiptCredential: ReceiptCredential) throws  -> ReceiptCredentialPresentation {
    var newContents: [UInt8] = Array(repeating: 0, count: ReceiptCredentialPresentation.SIZE)

    let ffi_return = FFI_ServerPublicParams_createReceiptCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForFFI(), UInt32(serverPublicParams.getInternalContentsForFFI().count), randomness, UInt32(randomness.count), receiptCredential.getInternalContentsForFFI(), UInt32(receiptCredential.getInternalContentsForFFI().count), &newContents, UInt32(newContents.count))
    if (ffi_return == Native.FFI_RETURN_INPUT_ERROR) {
      throw ZkGroupException.VerificationFailed
    }

    if (ffi_return != Native.FFI_RETURN_OK) {
      throw ZkGroupException.ZkGroupError
    }

    do {
      return try ReceiptCredentialPresentation(contents: newContents)
    } catch ZkGroupException.InvalidInput {
      throw ZkGroupException.AssertionError
    }

  }

}
