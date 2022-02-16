//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Thu Feb 10 18:29:20 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:test/test.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xpath_selector/xpath_selector.dart';

void main() {
  test('test with a document', () {
    final xml = File('./test/static/valid_saml.xml').readAsStringSync();
    final signature = XPath.xml(xml)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });
}