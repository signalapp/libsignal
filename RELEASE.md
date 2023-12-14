# Making a libsignal release

## 0. Make sure all CI tests are passing on the latest commit

Check GitHub to see if the latest commit has all tests passing, including the nightly "Slow Tests". If not, fix the tests before releasing! (You can run the Slow Tests manually under the repository Actions tab on GitHub.)

## 1. Update the library version

The first version component should always be 0, to indicate that Signal does not promise stability between releases of the library.

A change is "breaking" if it will require updates in any of the Signal client apps or server components, or in external Rust clients of libsignal-protocol, zkgroup, poksho, attest, device-transfer, or signal-crypto. If there are any breaking changes, increase the second version component and reset the third to 0. Otherwise, increase the third version component.

```
bin/update_versions.py 0.x.y
cargo check --workspace --all-features # make sure Cargo.lock is updated
bin/regenerate_acknowledgments.sh # include the new version number in the acknowledgments
```

## 2. Record the code size for the Java library

On GitHub, under the Java tests for the most recent commit, copy the code size computed in the "java/check_code_size.py" step into a new entry in java/code_size.json.

## 3. Commit the version change and tag with release notes

```
git commit -am 'Bump to version v0.x.y'
git tag -a v0.x.y
```

Take a look at a past release for examples of the format:

```
v0.8.3

- Fixed several issues running signal-crypto operations on 32-bit
  platforms.
- Removed custom implementation of AES-GCM-SIV, AES, AES-CTR, and
  GHash in favor of the implementations from RustCrypto. The interface
  presented to Java, Swift, and TypeScript clients has not changed.
- Updated several Rust dependencies.
- Java: Exposed the tag size for Aes256GcmDecryption.
```

(You might think repeating the version number in the summary field is redundant, but GitHub shows it as a title.)

## 4. Push the version bump and tag to GitHub

Note that both the tag *and* the branch need to be pushed.

## 5. Tag signalapp/boring if needed

If the depended-on version of `boring` has changed (check Cargo.lock), tag the commit in the public [signalapp/boring][] repository.

```
# In the checkout for signalapp/boring
git tag -a libsignal-v0.x.y -m 'libsignal v0.x.y' BORING_COMMIT_HASH
git push origin libsignal-v0.x.y
```

[signalapp/boring]: https://github.com/signalapp/boring

## 6. Submit to package repositories as needed

### Android and Server: Sonatype

In the signalapp/libsignal repository on GitHub, run the "Upload Java libraries to Sonatype" action on the tag you just made. Then go to [Maven Central][] and wait for the build to show up (it can take up to an hour).

[Maven Central]: https://central.sonatype.com/artifact/org.signal/libsignal-client/versions

### Node: NPM

In the signalapp/libsignal repository on GitHub, run the "Publish to NPM" action on the tag you just made. Leave the "NPM Tag" as "latest".

### iOS: Build Artifacts

In the signalapp/libsignal repository on GitHub, run the "Build iOS Artifacts" action on the tag you just made. Share the resulting checksum with whoever will update the iOS app repository.
