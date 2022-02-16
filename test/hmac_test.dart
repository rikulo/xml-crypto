//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Mon Feb 14 11:59:13 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:test/test.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xpath_selector/xpath_selector.dart';

void main() {
  SignedXml.enableHMAC();

  test('test validating HMAC signature', () {
    final xml = File('./test/static/hmac_signature.xml').readAsStringSync();
    final signature = XPath.xml(xml)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/hmac.key');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });

  test('test HMAC signature with incorrect key', () {
    final xml = File('./test/static/hmac_signature.xml').readAsStringSync();
    final signature = XPath.xml(xml)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/hmac-foobar.key');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isFalse);
  });

  test('test create and validate HMAC signature', () {
    final xml = '<library>'
    '<book>'
    '<name>Harry Potter</name>'
    '</book>'
    '</library>';
    final sig = SignedXml();
    sig.signingKey = File('./test/static/hmac.key').readAsBytesSync();
    sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
    sig.addReference("//*[local-name()='book']");
    sig.computeSignature(xml);

    final signature = XPath.xml(sig.signedXml)
        .query("/*/*[local-name()='Signature']") // FIXME should use namespace-uri()
        .node?.node;

    final verify = SignedXml();
    verify.keyInfoProvider = FileKeyInfo('./test/static/hmac.key');
    verify.loadSignature(signature);
    expect(verify.checkSignature(sig.signedXml), isTrue);
  });
}