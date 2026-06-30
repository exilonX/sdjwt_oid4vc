import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('DcqlQuery.fromJson', () {
    test('reads credentials, vct values and claim paths', () {
      final query = DcqlQuery.fromJson({
        'credentials': [
          {
            'id': 'c1',
            'format': 'dc+sd-jwt',
            'meta': {
              'vct_values': ['https://t/extras/v1'],
            },
            'claims': [
              {
                'path': ['given_name'],
              },
              {
                'path': ['address', 'street'],
              },
              {
                'path': [0],
              },
            ],
          },
        ],
      });

      expect(query.credentials, hasLength(1));
      final credential = query.credentials.single;
      expect(credential.id, 'c1');
      expect(credential.format, 'dc+sd-jwt');
      expect(credential.vctValues, ['https://t/extras/v1']);
      // Only the single-segment string path is a usable claim name.
      expect(credential.claimNames, ['given_name']);
      expect(credential.claims, hasLength(3));
      expect(credential.claims[1].name, isNull); // multi-segment
      expect(credential.claims[2].name, isNull); // array index
    });

    test('defaults gracefully for a bare credential query', () {
      final query = DcqlQuery.fromJson({
        'credentials': [
          {'id': 'c1'},
        ],
      });
      final credential = query.credentials.single;
      expect(credential.format, isNull);
      expect(credential.vctValues, isEmpty);
      expect(credential.claims, isEmpty);
      expect(credential.claimNames, isEmpty);
    });

    test('throws when there is no credentials array', () {
      expect(
        () => DcqlQuery.fromJson(const {}),
        throwsA(isA<PresentationError>()),
      );
    });
  });
}
