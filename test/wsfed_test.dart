//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Mon Feb 14 17:28:06 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:test/test.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xml_crypto/src/utils.dart';

void main() {
  test('test validating WS-Fed Metadata', () {
    final xml = File('./test/static/wsfederation_metadata.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = findFirstOrNull(
      doc,
      "/*/*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
    );

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/wsfederation_metadata.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });
}
