/// A source of the current time, in **seconds since the Unix epoch**.
///
/// Every place the protocol stamps an `iat` takes one of these. It defaults to
/// the system clock for convenience, but tests inject a fixed value so token
/// contents are deterministic — there is no hidden `DateTime.now()` anywhere in
/// the signing paths.
typedef Clock = int Function();

/// The real wall clock, truncated to whole seconds (JWT `iat`/`exp` are
/// `NumericDate`, i.e. seconds).
int systemClock() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
