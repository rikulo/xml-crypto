import 'dart:io';

import 'package:test/test.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xml_crypto/src/utils.dart';

void main() {
  group('ECDSA tests', () {
    test('validates an external ecdsa-sha256 signature', () {
      final xml = File('./test/static/ecdsa_signature.xml').readAsStringSync();
      final doc = parseFromString(xml);
      final signature = findFirstOrNull(
        doc,
        "/*/*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
      );

      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/ecdsa_public.pem');
      sig.loadSignature(signature);

      expect(sig.checkSignature(xml), isTrue);
      expect(
        sig.signatureAlgorithm,
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
      );
    });

    test('creates and validates an ecdsa-sha256 signature', () {
      const xml = '<library><book><name>Harry Potter</name></book></library>';
      final sig = SignedXml()
        ..signingKey = File('./test/static/ecdsa_private.pem').readAsBytesSync()
        ..signatureAlgorithm =
            'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
        ..addReference("//*[local-name()='book']", [
          'http://www.w3.org/2001/10/xml-exc-c14n#',
        ], 'http://www.w3.org/2001/04/xmlenc#sha256');

      sig.computeSignature(xml);

      final signedDoc = parseFromString(sig.signedXml);
      final signature = findFirstOrNull(
        signedDoc,
        "/*/*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
      );

      final verify = SignedXml();
      verify.keyInfoProvider = FileKeyInfo('./test/static/ecdsa_public.pem');
      verify.loadSignature(signature);

      expect(verify.checkSignature(sig.signedXml), isTrue);
      expect(
        sig.signatureXml,
        contains(
          'Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"',
        ),
      );
    });
  });
}
