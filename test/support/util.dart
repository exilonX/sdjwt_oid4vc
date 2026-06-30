/// A salt generator that hands out [salts] in order — deterministic disclosures
/// for tests.
String Function() seqSalts(List<String> salts) {
  var index = 0;
  return () => salts[index++];
}

/// A fixed clock (epoch seconds) for deterministic `iat` values.
int Function() fixedClock(int epochSeconds) => () => epochSeconds;
