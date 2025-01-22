# Making a libsignal release

## 0. Make sure all CI tests are passing on the latest commit

Check GitHub to see if the latest commit has all tests passing, including the nightly "Slow Tests". If not, fix the tests before releasing! (You can run the Slow Tests manually under the repository Actions tab on GitHub.)

## 1. Tag the release with its version and release notes

Create a new tag for this release version. You can find the anticipated version of this release at the top of RELEASE_NOTES.md. This should be kept up to date by contributors as changes are merged in. 

Verify that the top line in RELEASE_NOTES.md is the correct version according to the versioning methodology, then run this command:

```
git tag -a --edit "$(head -n1 RELEASE_NOTES.md)" -F RELEASE_NOTES.md
```

An editor will pop up to give you one final chance to edit the release notes associated with the tag.

The release notes will look something like: 

```
v0.x.y

- Bar: Added a fancy new feature
- Fixed a bug in the foo crate
- Android: Exposed baz to Java clients
```

v0.x.y is the version of the release, and should be the name of the tag. The changes are then listed in arbitrary order. It's important that the tag comment also includes the version number as the first line, because GitHub formats it as a title.

If it all looks good, save and exit in the editor to finalize the tag.

## 2. Push the tag to GitHub

Push the tag to the appropriate remote(s) via `git push <remote> v0.x.y`.

## 3. Submit to package repositories as needed

### Android and Server: Sonatype

In the signalapp/libsignal repository on GitHub, run the "Upload Java libraries to Sonatype" action on the tag you just made. Then go to [Maven Central][] and wait for the build to show up (it can take up to an hour).

[Maven Central]: https://central.sonatype.com/artifact/org.signal/libsignal-client/versions

### Node: NPM

In the signalapp/libsignal repository on GitHub, run the "Publish to NPM" action on the tag you just made. Leave the "NPM Tag" as "latest".

### iOS: Build Artifacts

In the signalapp/libsignal repository on GitHub, run the "Build iOS Artifacts" action on the tag you just made. Share the resulting checksum with whoever will update the iOS app repository.

## 4. Reset the repository to prepare for the next release

### 4.1. Record the code size for the Java library for the previous release

On GitHub, under the Java tests for the commit you just tagged as the release, copy the code size computed for the "current" commit in the "java/check_code_size.py" step into a new entry in java/code_size.json. The version for the new entry is the same as the version for the release you made, i.e. v0.x.y, not v0.x.(y+1).

### 4.2. Clear the Release Notes

As we work, we keep updated running release notes for *just* the next release in RELEASE_NOTES.md. Because you just made a release that included all the changes previously in RELEASE_NOTES.md, it's now time to reset RELEASE_NOTES.md

We always start by presuming the next release will not be a breaking one. So, if the last release was v0.x.y, the next release is always presumed to be v0.x.(y+1) until a breaking change is merged.

Edit RELEASE_NOTES.md so that it just contains the next version number on its own line, like so:

```
v0.x.y+1

```

### Versioning Methodology

The first version component should always be 0, to indicate that Signal does not promise stability between releases of the library.

A change is "breaking" if it will require updates in any of the Signal client apps or server components, or in external Rust clients of libsignal-protocol, zkgroup, poksho, attest, device-transfer, or signal-crypto. If there are any breaking changes, increase the second version component and reset the third to 0. Otherwise, increase the third version component.

### 4.3. Update the version number to the presumed next version number

Run the following commands with that version to update the version number throughout the repository:

```
bin/update_versions.py $(head -n 1 RELEASE_NOTES.md)
cargo check --workspace --all-features # make sure Cargo.lock is updated
```

#### 4.4. Commit all of these changes to main

Commit all these changes in a single commit to main:

```
git commit -am "Reset for version $(head -n1 RELEASE_NOTES.md)"
```

#### 4.5. Push the reset commit to GitHub

Finally, push the main branch with this commit to the proper remote:

```
git push <remote> main
```
