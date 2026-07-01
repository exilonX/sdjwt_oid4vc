# Publishing to pub.dev

How to cut a release of `sdjwt_oid4vc`. The first publish is manual (it creates
the package and registers you as uploader); every release after that is
automated over GitHub OIDC by pushing a version tag.

## Version to publish first

The package is at **`0.1.0-dev.1`** (see `pubspec.yaml` / `CHANGELOG.md`) — the
first pre-release. Publishing a `-dev.N` pre-release means `pub get` only
resolves it when a consumer explicitly opts in (`sdjwt_oid4vc: ^0.1.0-dev.1`),
which is exactly what you want while the API settles before `0.1.0`.

> The only hard rule is that each *subsequent* publish must have a strictly
> higher version than the last (`0.1.0-dev.2`, … then `0.1.0`).

## 1. Pre-flight (local, must all be clean)

```sh
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test                              # 100% line coverage, all green
dart run example/sdjwt_oid4vc_example.dart
dart pub publish --dry-run             # packaging/metadata gate
```

`--dry-run` must report **no warnings**. It checks the things pub.dev scores:
`description` length (60–180 chars), `LICENSE`, `CHANGELOG.md`, an `example/`,
resolvable `repository`/`homepage`, and total package size. The
`Release checks` CI job runs this on every PR, so if CI is green this passes.

## 2. First publish (manual — creates the package)

Automated publishing can only be configured on a package that already exists, so
the very first upload is done by hand from a clean checkout of `main`:

```sh
git switch main && git pull
dart pub login          # opens a browser; sign in with the Google account
                        # that will own the package
dart pub publish        # review the file list, type "y"
```

This registers you as the package **uploader**. Keep this account secure — for
day-to-day releases you won't use it again (the tag-triggered workflow does).

> Tie the release to a tag so the source is reproducible:
> `git tag v0.1.0-dev.1 && git push origin v0.1.0-dev.1` (see step 4 — after
> automated publishing is on, the tag push *is* the release).

## 3. Configure automated publishing (one time, on pub.dev)

On <https://pub.dev/packages/sdjwt_oid4vc> → **Admin** tab:

1. **Automated publishing → Enable publishing from GitHub Actions.**
2. Repository: **`exilonX/sdjwt_oid4vc`**.
3. Tag pattern: **`v{{version}}`** (so tag `v0.1.0` publishes `version: 0.1.0`).
4. *(Recommended)* require a GitHub **Environment** named `pub.dev`. If you set
   this, add `with: { environment: pub.dev }` is not needed — instead protect it
   in GitHub repo **Settings → Environments** (add required reviewers) so a human
   approves each publish.

The workflow ([`.github/workflows/publish.yml`](.github/workflows/publish.yml))
already has `permissions: id-token: write` (required for OIDC) and calls the
official `dart-lang/setup-dart` reusable publish workflow, which verifies the
tag matches `pubspec.yaml`'s `version:` and publishes tokenlessly.

## 4. Every subsequent release (automated)

```sh
# 1. bump the version + changelog
#    pubspec.yaml:  version: 0.1.0-dev.3   (or 0.1.0, 0.1.1, …)
#    CHANGELOG.md:  new heading + notes
# 2. land it on main via PR, then from main:
git switch main && git pull
git tag v0.1.0-dev.3
git push origin v0.1.0-dev.3
```

Pushing the tag triggers `publish.yml`. Watch it: `gh run watch`. If you enabled
the `pub.dev` environment, approve the run in the Actions tab.

## 5. Optional — verified publisher

For the "verified publisher" badge, on the package **Admin** tab create/attach a
publisher tied to a domain you control (DNS TXT verification) and transfer the
package to it. Not required to publish; it just adds trust signalling.

## Post-publish checklist

- [ ] Package page renders (README, example, changelog, LICENSE detected).
- [ ] pub points / pana score has no easy wins left (`dart pub global activate
      pana && pana .` locally to preview).
- [ ] Add the pub badge to `README.md`:
      `[![pub package](https://img.shields.io/pub/v/sdjwt_oid4vc.svg)](https://pub.dev/packages/sdjwt_oid4vc)`
- [ ] In the consuming wallet, depend on the published version and drop any
      `dependency_overrides`.
