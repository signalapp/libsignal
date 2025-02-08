# Making a libsignal release

## 1. Run bin/prepare_release.py

We maintain a helper script, prepare_release.py, to automate most of the rote work involved in cutting a release.

This script:

1. Automatically checks to ensure the Continuous Integration tests pass.
2. Tags the release commit with the appropriate annotated tag, with the version number as the name and the release notes as the comment.
3. Prepares the repository for the next version, by:
  1. Recording the code size of the just-released version in the repository,
  2. Clearing RELEASE_NOTES.md and preparing it for new release notes for the presumed next version,
  3. Updating the version number references throughout the repository to match the presumed next version, and finally
  4. commiting all these changes in a single commit.

All these steps can be done manually if desired/needed, but the script makes it easier, incentivizing more frequent releases.

## 2. Push the release commit to signalapp/libsignal on GitHub

Once you have tagged a release commit using the script, you should push it to GitHub as discussed below. After you have pushed the tag, you can then kick off the submission of that version to the package repositories.

#### Pushing to Multiple Remotes

If you need to push the multiple remotes, you must take care, as it is a little tricky to ensure each remote ends up in the desired end state.

#### Pushing Only the Release to a Remote

If you want to push just the newly cut release to a remote, you need to push the following items:

1. All commits up to and including the tagged commit that marks the release. (This commit should be `HEAD~1` after running the `./bin/prepare_release.py` script.)
2. You should fast forward the main branch ref on that remote to point to that same commit.
3. You should also push the tag marking the release you just cut.

Pushing all these items generally looks something like this:

```
git push <remote> HEAD~1:main <release tag, e.g. v0.x.y>
```

#### Pushing the Release and the Preparation Commit to a Remote

If you want to push both the release and the preparation commit that resets the repository state in anticipation of the next commit to a remote, so that e.g. you can continue working on the next release, you need to push the following items:

1. All commits up to and including the preparation commit, which should be `HEAD` on after running `./bin/prepare_release.py`.
2. You should fast-forward the main branch ref to point to that preparation commit.
3. You should also push the tag marking the release you just cut.

Pushing all these items should generally look like:

```
git push <remote> HEAD:main <release tag, e.g. v0.x.y>
```

## 3. Submit to package repositories as needed

### Android and Server: Sonatype

In the signalapp/libsignal repository on GitHub, run the "Upload Java libraries to Sonatype" action on the tag you just made. Then go to [Maven Central][] and wait for the build to show up (it can take up to an hour).

[Maven Central]: https://central.sonatype.com/artifact/org.signal/libsignal-client/versions

### Node: NPM

In the signalapp/libsignal repository on GitHub, run the "Publish to NPM" action on the tag you just made. Leave the "NPM Tag" as "latest".

### iOS: Build Artifacts

In the signalapp/libsignal repository on GitHub, run the "Build iOS Artifacts" action on the tag you just made. Share the resulting checksum with whoever will update the iOS app repository.

## Appendix: Release Standards and Information

### Versioning Methodology

The first version component should always be 0, to indicate that Signal does not promise stability between releases of the library.

A change is "breaking" if it will require updates in any of the Signal client apps or server components, or in external Rust clients of libsignal-protocol, zkgroup, poksho, attest, device-transfer, or signal-crypto. If there are any breaking changes, increase the second version component and reset the third to 0. Otherwise, increase the third version component.

### Release Notes Formatting

As we work, we keep running release notes in RELEASE_NOTES.md.

The format of these release notes should generally look something like:

```
v0.x.y

- Bar: Added a fancy new feature
- Fixed a bug in the foo crate
- Android: Exposed baz to Java clients
```

v0.x.y is the version of the release. The changes are then listed in arbitrary order. It's important that the tag comment also includes the version number as the first line, because GitHub formats it as a title.