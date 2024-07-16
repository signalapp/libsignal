//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Message backup validation routines.
 *
 * @module MessageBackup
 */

import * as Native from '../Native';
import { Aci } from './Address';
import { InputStream } from './io';

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

/**
 * Key used to encrypt and decrypt a message backup bundle.
 */
export class MessageBackupKey {
  readonly _nativeHandle: Native.MessageBackupKey;

  /**
   * Create a public key from the given master key and ACI.
   *
   * `masterKeyBytes` should contain exactly 32 bytes.
   */
  public constructor(masterKeyBytes: Buffer, aci: Aci) {
    this._nativeHandle = Native.MessageBackupKey_New(
      masterKeyBytes,
      aci.getServiceIdFixedWidthBinary()
    );
  }
}

// This must match the Rust version of the enum.
export enum Purpose {
  DeviceTransfer = 0,
  RemoteBackup = 1,
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
 */
export async function validate(
  backupKey: MessageBackupKey,
  purpose: Purpose,
  inputFactory: InputStreamFactory,
  length: bigint
): Promise<ValidationOutcome> {
  const firstStream = inputFactory();
  const secondStream = inputFactory();
  return new ValidationOutcome(
    await Native.MessageBackupValidator_Validate(
      backupKey,
      firstStream,
      secondStream,
      length,
      purpose
    )
  );
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
