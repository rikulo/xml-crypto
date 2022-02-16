//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Thu Feb 10 10:01:51 CST 2022
// Author: rudyhuang

import 'package:test/test.dart';
import 'package:xml_crypto/src/enveloped_signature.dart';
import 'package:xpath_selector/xpath_selector.dart';

void testC14nCanonicalization(String xml, String xpath, String expected) {
  final elem = XPath.xml(xml).query(xpath).node?.node;
  if (elem == null) {
    throw Exception('$xpath not found in $xml');
  }

  final can = EnvelopedSignature();
  final result = can.process(elem);
  expect(result.toString(), expected);
}

void main() {
  test('Enveloped-signature canonicalization respects currentnode', () {
    final xml = '<x><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" /><y><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" /></y></x>';
    final xpath = "//*[local-name()='y']";
    final expected = '<y/>';

    testC14nCanonicalization(xml, xpath, expected);
  });
}