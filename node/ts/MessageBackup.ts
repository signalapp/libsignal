//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Message backup validation routines.
 *
 * @module MessageBackup
 */

import * as Native from './Native.js';
import { ErrorCode, LibSignalErrorBase } from './Errors.js';
import { BackupForwardSecrecyToken, BackupKey } from './AccountKeys.js';
import { Aci } from './Address.js';
import { InputStream } from './io.js';

export type InputStreamFactory = () => InputStream;

/**
 * Result of validating a message backup bundle.
 */
export class ValidationOutcome {
  /**
   * A developer-facing message about the error encountered during validation,
   * if any.
   */
  public errorMessage: string | null;

  /**
   * Information about unknown fields encountered during validation.
   */
  public unknownFieldMessages: string[];

  /**
   * `true` if the backup is valid, `false` otherwise.
   *
   * If this is `true`, there might still be messages about unknown fields.
   */
  public get ok(): boolean {
    return this.errorMessage == null;
  }

  constructor(outcome: Native.MessageBackupValidationOutcome) {
    const { errorMessage, unknownFieldMessages } = outcome;
    this.errorMessage = errorMessage;
    this.unknownFieldMessages = unknownFieldMessages;
  }
}

export type MessageBackupKeyInput = Readonly<
  | {
      accountEntropy: string;
      aci: Aci;
      forwardSecrecyToken?: BackupForwardSecrecyToken;
    }
  | {
      backupKey: BackupKey | Uint8Array;
      backupId: Uint8Array;
      forwardSecrecyToken?: BackupForwardSecrecyToken;
    }
>;

/**
 * Key used to encrypt and decrypt a message backup bundle.
 *
 * @see {@link BackupKey}
 */
export class MessageBackupKey {
  readonly _nativeHandle: Native.MessageBackupKey;

  /**
   * Create a backup bundle key from an account entropy pool and ACI.
   *
   * ...or from a backup key and ID, used when reading from a local backup, which may have been
   * created with a different ACI.
   *
   * The account entropy pool must be **validated**; passing an arbitrary string here is considered
   * a programmer error. Similarly, passing a backup key or ID of the wrong length is also an error.
   */
  public constructor(input: MessageBackupKeyInput) {
    if ('accountEntropy' in input) {
      const { accountEntropy, aci, forwardSecrecyToken } = input;
      this._nativeHandle = Native.MessageBackupKey_FromAccountEntropyPool(
        accountEntropy,
        aci.getServiceIdFixedWidthBinary(),
        forwardSecrecyToken?.contents ?? null
      );
    } else {
      const { backupId, forwardSecrecyToken } = input;
      let { backupKey } = input;
      if (backupKey instanceof BackupKey) {
        backupKey = backupKey.contents;
      }
      this._nativeHandle = Native.MessageBackupKey_FromBackupKeyAndBackupId(
        backupKey,
        backupId,
        forwardSecrecyToken?.contents ?? null
      );
    }
  }

  /** An HMAC key used to sign a backup file. */
  public get hmacKey(): Uint8Array {
    return Native.MessageBackupKey_GetHmacKey(this);
  }

  /** An AES-256-CBC key used to encrypt a backup file. */
  public get aesKey(): Uint8Array {
    return Native.MessageBackupKey_GetAesKey(this);
  }
}

// This must match the Rust version of the enum.
export enum Purpose {
  DeviceTransfer = 0,
  RemoteBackup = 1,
  TakeoutExport = 2,
}

/**
 * Validate a backup file
 *
 * @param backupKey The key to use to decrypt the backup contents.
 * @param purpose Whether the backup is intended for device-to-device transfer or remote storage.
 * @param inputFactory A function that returns new input streams that read the backup contents.
 * @param length The exact length of the input stream.
 * @returns The outcome of validation, including any errors and warnings.
 * @throws IoError If an IO error on the input occurs.
 *
 * @see OnlineBackupValidator
 */
export async function validate(
  backupKey: MessageBackupKey,
  purpose: Purpose,
  inputFactory: InputStreamFactory,
  length: bigint
): Promise<ValidationOutcome> {
  let firstStream: InputStream | undefined;
  let secondStream: InputStream | undefined;
  try {
    firstStream = inputFactory();
    secondStream = inputFactory();
    return new ValidationOutcome(
      await Native.MessageBackupValidator_Validate(
        backupKey,
        firstStream,
        secondStream,
        length,
        purpose
      )
    );
  } finally {
    await firstStream?.close();
    await secondStream?.close();
  }
}

/**
 * An alternative to {@link validate()} that validates a backup frame-by-frame.
 *
 * This is much faster than using `validate()` because it bypasses the decryption and decompression
 * steps, but that also means it's validating less. Don't forget to call `finalize()`!
 *
 * Unlike `validate()`, unknown fields are treated as "soft" errors and logged, rather than
 * collected and returned to the app for processing.
 *
 * # Example
 *
 * ```
 * const validator = new OnlineBackupValidator(
 *     backupInfoProto.serialize(),
 *     Purpose.deviceTransfer)
 * repeat {
 *   // ...generate Frames...
 *   validator.addFrame(frameProto.serialize())
 * }
 * validator.finalize() // don't forget this!
 * ```
 */
export class OnlineBackupValidator {
  readonly _nativeHandle: Native.OnlineBackupValidator;

  /**
   * Initializes an OnlineBackupValidator from the given BackupInfo protobuf message.
   *
   * "Soft" errors will be logged, including unrecognized fields in the protobuf.
   *
   * @throws BackupValidationError on error
   */
  constructor(backupInfo: Uint8Array, purpose: Purpose) {
    this._nativeHandle = Native.OnlineBackupValidator_New(backupInfo, purpose);
  }

  /**
   * Processes a single Frame protobuf message.
   *
   * "Soft" errors will be logged, including unrecognized fields in the protobuf.
   *
   * @throws BackupValidationError on error
   */
  addFrame(frame: Uint8Array): void {
    Native.OnlineBackupValidator_AddFrame(this, frame);
  }

  /**
   * Marks that a backup is complete, and does any final checks that require whole-file knowledge.
   *
   * "Soft" errors will be logged.
   *
   * @throws BackupValidationError on error
   */
  finalize(): void {
    Native.OnlineBackupValidator_Finalize(this);
  }
}

/**
 * An in-memory representation of a backup file used to compare contents.
 *
 * When comparing the contents of two backups:
 *   1. Create a `ComparableBackup` instance for each of the inputs.
 *   2. Check the `unknownFields()` value; if it's not empty, some parts of the
 *      backup weren't parsed and won't be compared.
 *   3. Produce a canonical string for each backup with `comparableString()`.
 *   4. Compare the canonical string representations.
 *
 * The diff of the canonical strings (which may be rather large) will show the
 * differences between the logical content of the input backup files.
 */
export class ComparableBackup {
  readonly _nativeHandle: Native.ComparableBackup;
  constructor(handle: Native.ComparableBackup) {
    this._nativeHandle = handle;
  }

  /**
   * Read an unencrypted backup file into memory for comparison.
   *
   * @param purpose Whether the backup is intended for device-to-device transfer or remote storage.
   * @param input An input stream that reads the backup contents.
   * @param length The exact length of the input stream.
   * @returns The in-memory representation.
   * @throws BackupValidationError If an IO error occurs or the input is invalid.
   */
  public static async fromUnencrypted(
    purpose: Purpose,
    input: InputStream,
    length: bigint
  ): Promise<ComparableBackup> {
    const handle = await Native.ComparableBackup_ReadUnencrypted(
      input,
      length,
      purpose
    );
    return new ComparableBackup(handle);
  }

  /**
   * Produces a string representation of the contents.
   *
   * The returned strings for two backups will be equal if the backups contain
   * the same logical content. If two backups' strings are not equal, the diff
   * will show what is different between them.
   *
   * @returns a canonical string representation of the backup
   */
  public comparableString(): string {
    return Native.ComparableBackup_GetComparableString(this);
  }

  /**
   * Unrecognized protobuf fields present in the backup.
   *
   * If this is not empty, some parts of the backup were not recognized and
   * won't be present in the string representation.
   */
  public get unknownFields(): Array<string> {
    return Native.ComparableBackup_GetUnknownFields(this);
  }
}

/**
 * The output from processing a single frame for JSON export.
 *
 * There are four possibilities:
 * - `line` present, `errorMessage` absent - the common case, a frame converted (and possibly sanitized)
 *   with no problems.
 * - `line` present, `errorMessage` present - the frame has been converted, but would have failed
 *   validation.
 * - `line` absent, `errorMessage` absent - the frame has been filtered out wholesale.
 * - `line` absent, `errorMessage` present - the frame has been filtered out wholesale, but would have
 *   failed validation had it not been filtered out.
 */
export type BackupJsonFrameResult = {
  line?: string;
  errorMessage?: string;
};

export type BackupJsonFinishResult = { errorMessage?: string };

/**
 * Streaming exporter that produces a human-readable JSON representation of a backup.
 *
 * Validation feedback returned by this exporter is best-effort and intended for logging or
 * diagnostics. Even when a frame reports a validation error, the serialized line is still
 * produced so consumers can continue streaming the export.
 */
export class BackupJsonExporter {
  private constructor(readonly _nativeHandle: Native.BackupJsonExporter) {}

  /**
   * Initializes the streaming exporter and returns the first set of output lines.
   * @param backupInfo The serialized BackupInfo protobuf without a varint header.
   * @param [options] Additional configuration for the exporter.
   * @param [options.validate=true] Whether to run semantic validation on the backup.
   * @returns An object containing the exporter and the first chunk of output, containing the backup info.
   * @throws Error if the input is invalid.
   */
  public static start(
    backupInfo: Uint8Array,
    options?: { validate?: boolean }
  ): { exporter: BackupJsonExporter; chunk: string } {
    const shouldValidate = options?.validate ?? true;
    const handle = Native.BackupJsonExporter_New(backupInfo, shouldValidate);
    const exporter = new BackupJsonExporter(handle);
    const chunk = Native.BackupJsonExporter_GetInitialChunk(exporter);
    return { exporter, chunk };
  }

  /**
   * Validates and exports a human-readable JSON representation of backup frames.
   * @param frames One or more varint delimited Frame serialized protobuf messages.
   * @returns An array containing the line and any validation error for each frame.
   * Frames that report validation errors still include their serialized `line`, so consumers
   * should continue processing the export and surface the errors for observability rather than
   * aborting.
   * @throws Error if the input data cannot be parsed.
   */
  public exportFrames(frames: Uint8Array): BackupJsonFrameResult[] {
    return Native.BackupJsonExporter_ExportFrames(this, frames);
  }

  /**
   * Completes the validation and export of the previously exported frames.
   *
   * Per-frame validation errors are reported via `exportFrames`, so callers
   * should inspect earlier results even if this returns with no error.
   * @returns The outcome of the final validation stage.
   */
  public finish(): BackupJsonFinishResult {
    try {
      Native.BackupJsonExporter_Finish(this);
      return {};
    } catch (error: unknown) {
      if (LibSignalErrorBase.is(error, ErrorCode.BackupValidation)) {
        return { errorMessage: error.message };
      }
      throw error;
    }
  }
}
