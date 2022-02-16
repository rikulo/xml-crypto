//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Mon Feb 14 17:28:06 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:test/test.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xpath_selector/xpath_selector.dart';

void main() {
  test('test validating WS-Fed Metadata', () {
    final xml = File('./test/static/wsfederation_metadata.xml').readAsStringSync();
    final signature = XPath.xml(xml)
        .query("/*/*[local-name()='Signature']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/wsfederation_metadata.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });
}