//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Mon Feb 14 16:09:38 CST 2022
// Author: rudyhuang

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';
import 'package:ninja/ninja.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';
import 'package:xml_crypto/src/signed_xml.dart';
import 'package:xml_crypto/src/utils.dart';
import 'package:xpath_selector_xml_parser/xpath_selector_xml_parser.dart';

void verifyComputeSignature(String xml, String expectedFile, List<String> referencesXPath) {
  final sig = SignedXml();
  sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
  sig.keyInfo = null;

  for (final ref in referencesXPath) {
    sig.addReference(ref);
  }

  sig.computeSignature(xml);
  final signed = sig.signedXml;
  final expectedContent = File(expectedFile).readAsStringSync();
  expect(signed, expectedContent, reason: 'signature xml different than expected');
}

void main() {
  group('integration tests', () {
    test('verify signature', () {
      // Since XmlDocument will keep non self-closing tags as is, we changed the test xml to use self-closing tags.
      final xml = "<root><x xmlns=\"ns\"/><y z_attr=\"value\" a_attr1=\"foo\"/><z><ns:w ns:attr=\"value\" xmlns:ns=\"myns\"/></z></root>";
      verifyComputeSignature(xml, './test/static/integration/expectedVerify.xml', [
        "//*[local-name()='x']",
        "//*[local-name()='y']",
        "//*[local-name()='w']",
      ]);
    });

    test('verify signature of complex element', () {
      final xml = "<library>"
          "<book>"
          "<name>Harry Potter</name>"
          "<author id=\"123456789\">"
          "<firstName>Joanne K</firstName>"
          "<lastName>Rowling</lastName>"
          "</author>"
          "</book>"
          "</library>";
      verifyComputeSignature(xml, './test/static/integration/expectedVerifyComplex.xml', [
        "//*[local-name()='book']",
      ]);
    });

    test('empty URI reference should consider the whole document', () {
      final xml = "<library>"
          "<book>"
          "<name>Harry Potter</name>"
          "</book>"
          "</library>";
      final signature = parseFromString(
          '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
              '<SignedInfo>'
              '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
              '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
              '<Reference URI="">'
              '<Transforms>'
              '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
              '</Transforms>'
              '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
              '<DigestValue>1tjZsV007JgvE1YFe1C8sMQ+iEg=</DigestValue>'
              '</Reference>'
              '</SignedInfo>'
              '<SignatureValue>FONRc5/nnQE2GMuEV0wK5/ofUJMHH7dzZ6VVd+oHDLfjfWax/lCMzUahJxW1i/dtm9Pl0t2FbJONVd3wwDSZzy6u5uCnj++iWYkRpIEN19RAzEMD1ejfZET8j3db9NeBq2JjrPbw81Fm7qKvte6jGa9ThTTB+1MHFRkC8qjukRM=</SignatureValue>'
              '</Signature>');
      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/client_public.pem');
      sig.loadSignature(signature.rootElement);
      expect(sig.checkSignature(xml), isTrue);
    });

    test('add canonicalization if output of transforms will be a node-set rather than an octet stream', () {
      var xml = File('./test/static/windows_store_signature.xml').readAsStringSync();
      // Make sure that whitespace in the source document is removed -- see xml-crypto issue #23 and post at
      //   http://webservices20.blogspot.co.il/2013/06/validating-windows-mobile-app-store.html
      // This regex is naive but works for this test case; for a more general solution consider
      //   the xmldom-fork-fixed library which can pass {ignoreWhiteSpace: true} into the Dom constructor.
      xml = xml.replaceAll(RegExp(r'>\s*<'), '><');

      final doc = parseFromString(xml);
      final signature = XmlXPath.node(doc)
          .query("//*//*[local-name()='Signature']") // FIXME should use namespace-uri()
          .node?.node;

      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/windows_store_certificate.pem');
      sig.loadSignature(signature);
      expect(sig.checkSignature(xml), isTrue);
    });

    test('signature with inclusive namespaces', () {
      final xml = File('./test/static/signature_with_inclusivenamespaces.xml').readAsStringSync();
      final doc = parseFromString(xml);
      final signature = XmlXPath.node(doc)
          .query("//*//*[local-name()='Signature']") // FIXME should use namespace-uri()
          .node?.node;

      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/signature_with_inclusivenamespaces.pem');
      sig.loadSignature(signature);
      expect(sig.checkSignature(xml), isTrue);
    });

    test('signature with inclusive namespaces with unix line separators', () {
      final xml = File('./test/static/signature_with_inclusivenamespaces_lines.xml').readAsStringSync();
      final doc = parseFromString(xml);
      final signature = XmlXPath.node(doc)
          .query("//*//*[local-name()='Signature']") // FIXME should use namespace-uri()
          .node?.node;

      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/signature_with_inclusivenamespaces.pem');
      sig.loadSignature(signature);
      expect(sig.checkSignature(xml), isTrue);
    });

    test('signature with inclusive namespaces with windows line separators', () {
      final xml = File('./test/static/signature_with_inclusivenamespaces_lines_windows.xml').readAsStringSync();
      final doc = parseFromString(xml);
      final signature = XmlXPath.node(doc)
          .query("//*//*[local-name()='Signature']") // FIXME should use namespace-uri()
          .node?.node;

      final sig = SignedXml();
      sig.keyInfoProvider = FileKeyInfo('./test/static/signature_with_inclusivenamespaces.pem');
      sig.loadSignature(signature);
      expect(sig.checkSignature(xml), isTrue);
    });

    test('should create single root xml document when signing inner node', () {
      final xml = '<library>'
          '<book>'
          '<name>Harry Potter</name>'
          '</book>'
          '</library>';
      final sig = SignedXml();
      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='book']");
      sig.computeSignature(xml);

      final signed = sig.signedXml;
      print(signed);
      final doc = parseFromString(signed);

      expect(doc.rootElement.name.local, "library", reason: 'root node = <library>.');
      expect(doc.children.length, 1, reason: 'only one root node is expected.');
      expect(doc.rootElement.children.length, 2, reason: '<library> should have two child nodes : <book> and <Signature>');
    });
  });

  group('unit tests', () {
    test('signer adds increasing id attributes to elements', () {
      // verifyAddsId('wssecurity', 'equal'); FIXME: xpath namespace support is broken
      verifyAddsId('', 'different');
    });

    test('signer adds references with namespaces', () {
      verifyReferenceNS();
    });

    test('signer does not duplicate existing id attributes', () {
      verifyDoesNotDuplicateIdAttributes('', '');
      verifyDoesNotDuplicateIdAttributes('wssecurity', 'wsu:');
    });

    test('signer adds custom attributes to the signature root node', () {
      verifyAddsAttrs();
    });

    test('signer appends signature to the root node by default', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml();

      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='name']");
      sig.computeSignature(xml);

      final doc = parseFromString(sig.signedXml);

      expect(doc.rootElement.lastElementChild!.name.local, 'Signature',
          reason: 'the signature must be appended to the root node by default');
    });

    test('signer appends signature to a reference node', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml();

      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='repository']");
      sig.computeSignature(xml, opts: {
        'location': {
          'reference': '/root/name',
          'action': 'append'
        }
      });

      final doc = parseFromString(sig.signedXml);
      final referenceNode = XmlXPath.node(doc).query('/root/name').node!.node;
      expect(referenceNode.lastElementChild!.name.local, 'Signature',
          reason: 'the signature should be appended to root/name');
    });

    test('signer prepends signature to a reference node', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml();

      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='repository']");
      sig.computeSignature(xml, opts: {
        'location': {
          'reference': '/root/name',
          'action': 'prepend'
        }
      });

      final doc = parseFromString(sig.signedXml);
      final referenceNode = XmlXPath.node(doc).query('/root/name').node!.node;
      expect(referenceNode.firstElementChild!.name.local, 'Signature',
          reason: 'the signature should be prepended to root/name');
    });

    test('signer inserts signature before a reference node', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml();

      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='repository']");
      sig.computeSignature(xml, opts: {
        'location': {
          'reference': '/root/name',
          'action': 'before'
        }
      });

      final doc = parseFromString(sig.signedXml);
      final referenceNode = XmlXPath.node(doc).query('/root/name').node!.node;
      expect(referenceNode.previousElementSibling!.name.local, 'Signature',
          reason: 'the signature should be prepended to root/name');
    });

    test('signer inserts signature after a reference node', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml();

      sig.signingKey = File('./test/static/client.pem').readAsBytesSync();
      sig.addReference("//*[local-name()='repository']");
      sig.computeSignature(xml, opts: {
        'location': {
          'reference': '/root/name',
          'action': 'after'
        }
      });

      final doc = parseFromString(sig.signedXml);
      final referenceNode = XmlXPath.node(doc).query('/root/name').node!.node;
      expect(referenceNode.nextElementSibling!.name.local, 'Signature',
          reason: 'the signature should be prepended to root/name');
    });

    test('signer creates signature with correct structure', () {
      final xml = '<root><x xmlns="ns"/><y attr="value"/><z><w/></z></root>';
      final sig = SignedXml();

      SignedXml.canonicalizationAlgorithms['http://DummyTransformation'] = DummyTransformation();
      SignedXml.canonicalizationAlgorithms['http://DummyCanonicalization'] = DummyCanonicalization();
      SignedXml.hashAlgorithms['http://dummyDigest'] = DummyDigest();
      SignedXml.signatureAlgorithms['http://dummySignatureAlgorithm'] = DummySignatureAlgorithm();

      sig
        ..signatureAlgorithm = 'http://dummySignatureAlgorithm'
        ..keyInfoProvider = DummyKeyInfo()
        ..canonicalizationAlgorithm = 'http://DummyCanonicalization'
        ..addReference("//*[local-name()='x']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..addReference("//*[local-name()='y']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..addReference("//*[local-name()='w']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..computeSignature(xml);

      final expected = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
          "<SignedInfo>"
          "<CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"
          "<SignatureMethod Algorithm=\"dummy algorithm\"/>"
          "<Reference URI=\"#_0\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_1\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_2\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "</SignedInfo>"
          "<SignatureValue>dummy signature</SignatureValue>"
          "<KeyInfo>"
          "dummy key info"
          "</KeyInfo>"
          "</Signature>";
      expect(sig.signatureXml, expected, reason: 'wrong signature format');

      final expectedSignedXml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>"
          "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
          "<SignedInfo>"
          "<CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"
          "<SignatureMethod Algorithm=\"dummy algorithm\"/>"
          "<Reference URI=\"#_0\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_1\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_2\">"
          "<Transforms>"
          "<Transform Algorithm=\"dummy transformation\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<DigestValue>dummy digest</DigestValue>"
          "</Reference>"
          "</SignedInfo>"
          "<SignatureValue>dummy signature</SignatureValue>"
          "<KeyInfo>"
          "dummy key info"
          "</KeyInfo>"
          "</Signature>"
          "</root>";
      expect(sig.signedXml, expectedSignedXml, reason: 'wrong signedXml format');
      expect(sig.originalXmlWithIds, "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>",
        reason: 'wrong OriginalXmlWithIds');
    });

    test('signer creates signature with correct structure (with prefix)', () {
      final prefix = 'ds';
      final xml = '<root><x xmlns="ns"/><y attr="value"/><z><w/></z></root>';
      final sig = SignedXml();

      SignedXml.canonicalizationAlgorithms['http://DummyTransformation'] = DummyTransformation();
      SignedXml.canonicalizationAlgorithms['http://DummyCanonicalization'] = DummyCanonicalization();
      SignedXml.hashAlgorithms['http://dummyDigest'] = DummyDigest();
      SignedXml.signatureAlgorithms['http://dummySignatureAlgorithm'] = DummySignatureAlgorithm();

      sig
        ..signatureAlgorithm = 'http://dummySignatureAlgorithm'
        ..keyInfoProvider = DummyKeyInfoNS()
        ..canonicalizationAlgorithm = 'http://DummyCanonicalization'
        ..addReference("//*[local-name()='x']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..addReference("//*[local-name()='y']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..addReference("//*[local-name()='w']", ['http://DummyTransformation'], 'http://dummyDigest')
        ..computeSignature(xml, opts: {'prefix': prefix });

      final expected = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
          "<ds:SignedInfo>"
          "<ds:CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"
          "<ds:SignatureMethod Algorithm=\"dummy algorithm\"/>"
          "<ds:Reference URI=\"#_0\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "<ds:Reference URI=\"#_1\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "<ds:Reference URI=\"#_2\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "</ds:SignedInfo>"
          "<ds:SignatureValue>dummy signature</ds:SignatureValue>"
          "<ds:KeyInfo>"
          "<ds:dummy>dummy key info</ds:dummy>"
          "</ds:KeyInfo>"
          "</ds:Signature>";
      expect(sig.signatureXml, expected, reason: 'wrong signature format');

      final expectedSignedXml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>"
          "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
          "<ds:SignedInfo>"
          "<ds:CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"
          "<ds:SignatureMethod Algorithm=\"dummy algorithm\"/>"
          "<ds:Reference URI=\"#_0\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "<ds:Reference URI=\"#_1\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "<ds:Reference URI=\"#_2\">"
          "<ds:Transforms>"
          "<ds:Transform Algorithm=\"dummy transformation\"/>"
          "</ds:Transforms>"
          "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"
          "<ds:DigestValue>dummy digest</ds:DigestValue>"
          "</ds:Reference>"
          "</ds:SignedInfo>"
          "<ds:SignatureValue>dummy signature</ds:SignatureValue>"
          "<ds:KeyInfo>"
          "<ds:dummy>dummy key info</ds:dummy>"
          "</ds:KeyInfo>"
          "</ds:Signature>"
          "</root>";
      expect(sig.signedXml, expectedSignedXml, reason: 'wrong signedXml format');
      expect(sig.originalXmlWithIds, "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>",
          reason: 'wrong OriginalXmlWithIds');
    });

    test('signer creates correct signature values', () {
      final xml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>";
      final sig = SignedXml();
      sig.signingKey = File("./test/static/client.pem").readAsBytesSync();
      sig.keyInfoProvider = null;

      sig
        ..addReference("//*[local-name()='x']")
        ..addReference("//*[local-name()='y']")
        ..addReference("//*[local-name()='w']")
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final expected = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>"
          "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
          "<SignedInfo>"
          "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
          "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
          "<Reference URI=\"#_0\">"
          "<Transforms>"
          "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>"
          "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
          "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_1\">"
          "<Transforms>"
          "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
          "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>"
          "</Reference>"
          "<Reference URI=\"#_2\">"
          "<Transforms>"
          "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
          "</Transforms>"
          "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
          "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>"
          "</Reference>"
          "</SignedInfo>"
          "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>"
          "</Signature>"
          "</root>";
      expect(signedXml, expected, reason: 'wrong signature format');
    });

    test('signer creates correct signature values using async callback', () {
      final xml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>";
      SignedXml.signatureAlgorithms['http://dummySignatureAlgorithmAsync'] = DummySignatureAlgorithmAsync();
      final sig = SignedXml();
      sig
        ..signatureAlgorithm = 'http://dummySignatureAlgorithmAsync'
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference("//*[local-name()='x']")
        ..addReference("//*[local-name()='y']")
        ..addReference("//*[local-name()='w']")
        ..computeSignature(xml, callback: (err, _) {
          final signedXml = sig.signedXml;
          final expected = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>"
              "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
              "<SignedInfo>"
              "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
              "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
              "<Reference URI=\"#_0\">"
              "<Transforms>"
              "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>"
              "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
              "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>"
              "</Reference>"
              "<Reference URI=\"#_1\">"
              "<Transforms>"
              "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
              "</Transforms>"
              "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
              "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>"
              "</Reference>"
              "<Reference URI=\"#_2\">"
              "<Transforms>"
              "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
              "</Transforms>"
              "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
              "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>"
              "</Reference>"
              "</SignedInfo>"
              "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>"
              "</Signature>"
              "</root>";
          expect(expected, signedXml, reason: 'wrong signature format');
        });
    });

    test('correctly loads signature', () {
      passLoadSignature('./test/static/valid_signature.xml');
      passLoadSignature('./test/static/valid_signature.xml', true);
      passLoadSignature('./test/static/valid_signature_with_root_level_sig_namespace.xml');
    });

    test('verify valid signature', () {
      passValidSignature('./test/static/valid_signature.xml');
      passValidSignature('./test/static/valid_signature_with_lowercase_id_attribute.xml');
      // passValidSignature('./test/static/valid_signature wsu.xml', 'wssecurity'); // FIXME: wsu namespace
      passValidSignature('./test/static/valid_signature_with_reference_keyInfo.xml');
      passValidSignature('./test/static/valid_signature_with_whitespace_in_digestvalue.xml');
      passValidSignature('./test/static/valid_signature_utf8.xml');
      // passValidSignature('./test/static/valid_signature_with_unused_prefixes.xml'); // FIXME: wsu namespace
    });

    test('fail invalid signature', () {
      failInvalidSignature('./test/static/invalid_signature - signature value.xml');
      failInvalidSignature('./test/static/invalid_signature - hash.xml');
      failInvalidSignature('./test/static/invalid_signature - non existing reference.xml');
      failInvalidSignature('./test/static/invalid_signature - changed content.xml');
      // failInvalidSignature('./test/static/invalid_signature - wsu - invalid signature value.xml', 'wssecurity'); // FIXME: wsu namespace
      // failInvalidSignature('./test/static/invalid_signature - wsu - hash.xml', 'wssecurity'); // FIXME: wsu namespace
      // failInvalidSignature('./test/static/invalid_signature - wsu - non existing reference.xml', 'wssecurity'); // FIXME: wsu namespace
      // failInvalidSignature('./test/static/invalid_signature - wsu - changed content.xml', 'wssecurity'); // FIXME: wsu namespace
    });

    test('allow empty reference uri when signing', () {
      final xml = '<root><x /></root>';
      final sig = SignedXml()
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference("//*[local-name()='root']", ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'], 'http://www.w3.org/2000/09/xmldsig#sha1', '', '', '', true)
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final doc = parseFromString(signedXml);
      final uri = XmlXPath.node(doc).query("//*[local-name()='Reference']/@URI").attr;
      expect(uri, isEmpty, reason: 'uri should be empty but instead was $uri');
    });

    test('signer appends signature to a non-existing reference node', () {
      final xml = '<root><name>xml-crypto</name><repository>github</repository></root>';
      final sig = SignedXml()
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..addReference("//*[local-name()='repository']");

      expect(() => sig.computeSignature(xml, opts: {
        'location': {
          'reference': '/root/foobar',
          'action': 'append'
        }
      }), throwsArgumentError);
    });

    test('signer adds existing prefixes', () {
      final xml = '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"> '
        '<SOAP-ENV:Header> '
        '<wsse:Security '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"> '
        '<Assertion></Assertion> '
        '</wsse:Security> '
        '</SOAP-ENV:Header> '
        '</SOAP-ENV:Envelope>';
      final sig = SignedXml()
        ..keyInfoProvider = AssertionKeyInfo('_81d5fba5c807be9e9cf60c58566349b1')
        ..signingKey = File('./test/static/client.pem').readAsBytesSync();

      sig.computeSignature(xml, opts: {
        'prefix': 'ds',
        'location': {
          'reference': '//Assertion',
          'action': 'after'
        },
        'existingPrefixes': {
          'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
          'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        }
      });
      final result = sig.signedXml;
      expect(RegExp(r'xmlns:wsu=').allMatches(result).length, 1);
      expect(RegExp(r'xmlns:wsse=').allMatches(result).length, 1);
    });

    test('creates InclusiveNamespaces element when inclusiveNamespacesPrefixList is set on Reference',
        () {
      final xml = '<root><x /></root>';
      final sig = SignedXml();
      sig
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference(
            "//*[local-name()='root']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "",
            "",
            "prefix1 prefix2")
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final doc = parseFromString(signedXml);
      final inclusiveNamespaces = XmlXPath.node(doc).query("//*[local-name()='Reference']/*[local-name()='Transforms']/*[local-name()='Transform']/*[local-name()='InclusiveNamespaces']").nodes;
      expect(inclusiveNamespaces, hasLength(1), reason: 'InclusiveNamespaces element should exist');

      final prefixListAttribute = inclusiveNamespaces.first.attributes['PrefixList'];
      expect(prefixListAttribute, 'prefix1 prefix2', reason: 'InclusiveNamespaces element should have the correct PrefixList attribute value');
    });

    test('does not create InclusiveNamespaces element when inclusiveNamespacesPrefixList is not set on Reference',
        () {
      final xml = '<root><x /></root>';
      final sig = SignedXml();
      sig
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference(
            "//*[local-name()='root']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "",
            "",
            "")
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final doc = parseFromString(signedXml);
      final inclusiveNamespaces = XmlXPath.node(doc).query("//*[local-name()='Reference']/*[local-name()='Transforms']/*[local-name()='Transform']/*[local-name()='InclusiveNamespaces']").nodes;
      expect(inclusiveNamespaces, isEmpty, reason: 'InclusiveNamespaces element should not exist');
    });

    test('creates InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is set on SignedXml options',
        () {
      final xml = '<root><x /></root>';
      final sig = SignedXml('', {
        'inclusiveNamespacesPrefixList': "prefix1 prefix2"
      }); // Omit inclusiveNamespacesPrefixList property
      sig
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference(
            "//*[local-name()='root']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
            "http://www.w3.org/2000/09/xmldsig#sha1")
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final doc = parseFromString(signedXml);
      final inclusiveNamespaces = XmlXPath.node(doc).query("//*[local-name()='CanonicalizationMethod']/*[local-name()='InclusiveNamespaces']").nodes;
      expect(inclusiveNamespaces, hasLength(1), reason: 'InclusiveNamespaces element should exist inside CanonicalizationMethod');

      final prefixListAttribute = inclusiveNamespaces.first.attributes['PrefixList'];
      expect(prefixListAttribute, 'prefix1 prefix2', reason: 'InclusiveNamespaces element inside CanonicalizationMethod should have the correct PrefixList attribute value');
    });

    test('does not create InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is not set on SignedXml options',
        () {
      final xml = '<root><x /></root>';
      final sig = SignedXml(); // Omit inclusiveNamespacesPrefixList property
      sig
        ..signingKey = File('./test/static/client.pem').readAsBytesSync()
        ..keyInfoProvider = null
        ..addReference(
            "//*[local-name()='root']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
            "http://www.w3.org/2000/09/xmldsig#sha1")
        ..computeSignature(xml);
      final signedXml = sig.signedXml;
      final doc = parseFromString(signedXml);
      final inclusiveNamespaces = XmlXPath.node(doc).query("//*[local-name()='CanonicalizationMethod']/*[local-name()='InclusiveNamespaces']").nodes;
      expect(inclusiveNamespaces, isEmpty, reason: 'InclusiveNamespaces element should not exist inside CanonicalizationMethod');
    });
  });
}

void verifyAddsId(String mode, String nsMode) {
  final xml = "<root><x xmlns=\"ns\"></x><y attr=\"value\"></y><z><w></w></z></root>";
  final sig = SignedXml(mode);
  sig.signingKey = File('./test/static/client.pem').readAsBytesSync();

  sig.addReference("//*[local-name()='x']");
  sig.addReference("//*[local-name()='y']");
  sig.addReference("//*[local-name()='w']");

  sig.computeSignature(xml);
  final signedXml = sig.originalXmlWithIds;
  final doc = parseFromString(signedXml);

  final xpath = "//*[local-name()='{elem}' and @Id='_{id}']";
  // final op = nsMode == 'equal' ? '=' : '!='; FIXME: no namespace-uri() support
  // final xpath = "//*[local-name()='{elem}' and '_{id}' = @*[local-name()='Id' and namespace-uri()$op'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]";

  //verify each of the signed nodes now has an "Id" attribute with the right value
  nodeExists(doc, xpath.replaceFirst('{id}', '0').replaceFirst('{elem}', 'x'));
  nodeExists(doc, xpath.replaceFirst('{id}', '1').replaceFirst('{elem}', 'y'));
  nodeExists(doc, xpath.replaceFirst('{id}', '2').replaceFirst('{elem}', 'w'));
}

void nodeExists(XmlDocument doc, String xpath) {
  final node = XmlXPath.node(doc).query(xpath).node;
  expect(node, isNotNull, reason: 'xpath $xpath not found');
}

void verifyReferenceNS() {
  final xml = "<root xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><name wsu:Id=\"_1\">xml-crypto</name><repository wsu:Id=\"_2\">github</repository></root>";
  final sig = SignedXml("wssecurity");
  sig.signingKey = File('./test/static/client.pem').readAsBytesSync();

  // sig.addReference('//*[@wsu:Id]'); FIXME: xpath-selector doesn't support qualified names
  sig.addReference('//name');
  sig.addReference('//repository');

  sig.computeSignature(xml, opts: {
    'existingPrefixes': {
      'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    }
  });

  final signedXml = sig.signatureXml;
  final doc = parseFromString(signedXml);
  final references = XmlXPath.node(doc).query("//*[local-name()='Reference']").nodes;
  expect(references.length, 2);
}

void verifyDoesNotDuplicateIdAttributes(String mode, String prefix) {
  final xml = "<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' ${prefix}Id='_1'></x>";
  final sig = SignedXml(mode);
  sig.signingKey = File("./test/static/client.pem").readAsBytesSync();
  sig.addReference("//*[local-name()='x']");
  sig.computeSignature(xml);
  final signedXml = sig.originalXmlWithIds;
  final doc = parseFromString(signedXml);
  final attrs = XmlXPath.node(doc).query("//@*").attrs;
  expect(attrs.length, 2, reason: 'wrong number of attributes');
}

void verifyAddsAttrs() {
  final xml = "<root xmlns=\"ns\"><name>xml-crypto</name><repository>github</repository></root>";
  final sig = SignedXml();
  final attrs = {
    'Id': 'signatureTest',
    'data': 'dataValue',
    'xmlns': 'http://custom-xmlns#'
  };

  sig.signingKey = File("./test/static/client.pem").readAsBytesSync();

  sig.addReference("//*[local-name()='name']");

  sig.computeSignature(xml, opts: {
    'attrs': attrs
  });

  final signedXml = sig.signatureXml;
  final doc = parseFromString(signedXml);
  final signatureNode = doc.rootElement;

  expect(signatureNode.getAttribute('Id'), attrs['Id'],
      reason: 'Id attribute is not equal to the expected value: "${attrs['Id']}"');
  expect(signatureNode.getAttribute('data'), attrs['data'],
      reason: 'data attribute is not equal to the expected value: "${attrs['data']}"');
  expect(signatureNode.getAttribute('xmlns'), isNot(attrs['xmlns']),
      reason: 'xmlns attribute can not be overridden');
  expect(signatureNode.getAttribute('xmlns'), 'http://www.w3.org/2000/09/xmldsig#',
      reason: 'xmlns attribute is not equal to the expected value: "http://www.w3.org/2000/09/xmldsig#"');
}

class DummyKeyInfo extends KeyInfoProvider {
  @override
  String getKeyInfo(Uint8List? signingKey, String? prefix) => 'dummy key info';

  @override
  Uint8List getKey(String? keyInfo) => Uint8List(0);
}

class DummyKeyInfoNS extends KeyInfoProvider {
  @override
  String getKeyInfo(Uint8List? signingKey, String? prefix)
  => '<$prefix:dummy>dummy key info</$prefix:dummy>';

  @override
  Uint8List getKey(String? keyInfo) => Uint8List(0);
}

class DummyTransformation implements CanonicalizationAlgorithm<String> {
  @override
  String get algorithmName => 'dummy transformation';

  @override
  String process(XmlNode node, [Map<String, dynamic> options = const {}]) => '< x/>';
}

class DummyCanonicalization implements CanonicalizationAlgorithm<String> {
  @override
  String get algorithmName => 'dummy canonicalization';

  @override
  String process(XmlNode node, [Map<String, dynamic> options = const {}]) => '< x/>';
}

class DummyDigest implements HashAlgorithm {
  @override
  String getHash(String xml) => 'dummy digest';

  @override
  String get algorithmName => 'dummy digest algorithm';
}

class DummySignatureAlgorithm implements SignatureAlgorithm {
  @override
  String get algorithmName => 'dummy algorithm';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback])
  => 'dummy signature';

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback])
  => true;
}

class DummySignatureAlgorithmAsync implements SignatureAlgorithm {
  @override
  String get algorithmName => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]) {
    final rsa = RSAPrivateKey.fromPEM(utf8.decode(signingKey));
    final res = rsa.signSsaPkcs1v15ToBase64(utf8.encode(xml), hasher: EmsaHasher.sha1);
    //Do some asynchronous things here
    callback?.call(null, res);
    return '';
  }

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback])
  => true;
}

void passLoadSignature(String file, [bool toString = false]) {
  final xml = File(file).readAsStringSync();
  final doc = parseFromString(xml);
  final node = XmlXPath.node(doc).query("/*//*[local-name()='Signature']").node!.node; // FIXME namespace-uri()
  final sig = SignedXml();
  sig.loadSignature(toString ? node.toString() : node);

  expect(sig.canonicalizationAlgorithm, 'http://www.w3.org/2001/10/xml-exc-c14n#',
      reason: 'wrong canonicalization method');
  expect(sig.signatureAlgorithm, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
      reason: 'wrong signature method');
  expect(sig.signatureValue, "PI2xGt3XrVcxYZ34Kw7nFdq75c7Mmo7J0q7yeDhBprHuJal/KV9KyKG+Zy3bmQIxNwkPh0KMP5r1YMTKlyifwbWK0JitRCSa0Fa6z6+TgJi193yiR5S1MQ+esoQT0RzyIOBl9/GuJmXx/1rXnqrTxmL7UxtqKuM29/eHwF0QDUI=",
      reason: 'wrong signature value');

  final doc2 = parseFromString(sig.keyInfo!);
  final keyInfo = XmlXPath.node(doc2).query("//*[local-name()='KeyInfo']/*[local-name()='dummyKey']").node!.node;
  expect(keyInfo.firstChild?.text, '1234', reason: 'keyInfo clause not correctly loaded');
  expect(sig.references.length, 3);

  final digests = ['b5GCZ2xpP5T7tbLWBTkOl4CYupQ=', 'K4dI497ZCxzweDIrbndUSmtoezY=', 'sH1gxKve8wlU8LlFVa2l6w3HMJ0='];
  for (var i = 0; i < sig.references.length; i++) {
    final ref = sig.references[i];
    final expectedUri = '#_$i';
    expect(ref.uri, expectedUri, reason: 'wrong uri for index $i. expected: $expectedUri actual: ${ref.uri}');
    expect(ref.transforms.length, 1);
    expect(ref.transforms[0], 'http://www.w3.org/2001/10/xml-exc-c14n#');
    expect(ref.digestValue, digests[i]);
    expect(ref.digestAlgorithm, 'http://www.w3.org/2000/09/xmldsig#sha1');
  }
}

void passValidSignature(String file, [String mode = '']) {
  final xml = File(file).readAsStringSync();
  final res = verifySignature(xml, mode);
  expect(res, isTrue, reason: 'expected signature to be valid, but it was reported invalid');
}

bool verifySignature(String xml, String mode) {
  final doc = parseFromString(xml);
  final node = XmlXPath.node(doc).query("//*[local-name()='Signature']").node!.node; // FIXME namespace-uri()

  final sig = SignedXml(mode);
  sig.keyInfoProvider = FileKeyInfo('./test/static/client_public.pem');
  sig.loadSignature(node);
  final res = sig.checkSignature(xml);
  print(sig.validationErrors);
  return res;
}

void failInvalidSignature(String file, [String mode = '']) {
  final xml = File(file).readAsStringSync();
  final res = verifySignature(xml, mode);
  expect(res, isFalse, reason: 'expected signature to be invalid, but it was reported valid');
}

class AssertionKeyInfo implements KeyInfoProvider {
  final String assertionId;

  AssertionKeyInfo(this.assertionId);

  @override
  String getKeyInfo(Uint8List? signingKey, String? prefix)
  => '<wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" wsu:Id="0" '
      'xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"> '
      '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">$assertionId</wsse:KeyIdentifier>'
      '</wsse:SecurityTokenReference>';

  @override
  Uint8List getKey(String? keyInfo) => Uint8List(0);
}