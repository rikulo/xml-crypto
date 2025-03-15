//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Mon Feb 14 12:46:53 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:test/test.dart';
import 'package:xml/xml.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xml_crypto/src/utils.dart';
import 'package:xpath_selector_xml_parser/xpath_selector_xml_parser.dart';

void main() {
  test('test validating SAML response', () {
    final xml = File('./test/static/valid_saml.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });

  test('test validating wrapped assertion signature', () {
    final xml = File('./test/static/valid_saml_signature_wrapping.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final assertion = XmlXPath.node(doc)
        .query("//*[local-name()='Assertion']")
        .node?.node as XmlElement;
    final signature = assertion
        .queryXPath("//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(() => sig.checkSignature(xml), throwsArgumentError);
  });

  test('test validating SAML response where a namespace is defined outside the signed element', () {
    final xml = File('./test/static/saml_external_ns.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("//*//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/saml_external_ns.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isTrue);
  });

  test('test reference id does not contain quotes', () {
    final xml = File('./test/static/id_with_quotes.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final assertion = XmlXPath.node(doc)
        .query("//*[local-name()='Assertion']")
        .node?.node as XmlElement;
    final signature = assertion
        .queryXPath("//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(() => sig.checkSignature(xml), throwsUnsupportedError);
  });

  test('test validating SAML response WithComments', () {
    final xml = File('./test/static/valid_saml_withcomments.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isFalse);
  });

  test('test validating SAML response with digest comment', () {
    final xml = File('./test/static/valid_saml_with_digest_comment.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    sig.loadSignature(signature);
    expect(sig.checkSignature(xml), isFalse);
    expect(sig.references.first.digestValue, 'RnNjoyUguwze5w2R+cboyTHlkQk=');
  });

  test('test signature contains a `SignedInfo` node', () {
    final xml = File('./test/static/invalid_saml_no_signed_info.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("/*/*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/feide_public.pem');
    expect(() => sig.loadSignature(signature), throwsArgumentError);
  });

  test('test validation ignores an additional wrapped `SignedInfo` node', () {
    final xml = File('./test/static/saml_wrapped_signed_info_node.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/saml_external_ns.pem');
    sig.loadSignature(signature);
    expect(sig.references.length, 1);
    expect(sig.checkSignature(xml), isTrue);
  });

  test('test signature does not contain multiple `SignedInfo` nodes', () {
    final xml = File('./test/static/saml_multiple_signed_info_nodes.xml').readAsStringSync();
    final doc = parseFromString(xml);
    final signature = XmlXPath.node(doc)
        .query("//*[local-name()='Signature' and namespace()='ds']") // FIXME should use namespace-uri()
        .node?.node;

    final sig = SignedXml();
    sig.keyInfoProvider = FileKeyInfo('./test/static/saml_external_ns.pem');
    expect(() => sig.loadSignature(signature), throwsArgumentError);
  });
}