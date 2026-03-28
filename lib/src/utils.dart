//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 10:44:40 CST 2022
// Author: rudyhuang

import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';
import 'package:xpath_selector_xml_parser/xpath_selector_xml_parser.dart';

XmlAttribute? findAttr(XmlNode node, String localName, [String? namespace]) {
  for (final attr in node.attributes) {
    if (_attrEqualsExplicitly(attr, localName, namespace) ||
        (node is XmlElement &&
            _attrEqualsImplicitly(attr, localName, namespace, node))) {
      return attr;
    }
  }
  return null;
}

XmlNode findFirst(XmlElement doc, String xpath) {
  final nodes = doc.queryXPath(xpath), node = nodes.node;

  if (node == null) {
    throw ArgumentError("could not find xpath $xpath");
  }
  return node.node;
}

List<XmlElement> findChilds(XmlNode node, String localName,
    [String? namespace]) {
  if (node is XmlDocument) {
    node = node.rootElement;
  }

  final res = <XmlElement>[];
  for (final child in node.childElements) {
    if (child.name.local == localName &&
        (child.name.namespaceUri == namespace || namespace == null)) {
      res.add(child);
    }
  }
  return res;
}

bool _attrEqualsExplicitly(
    XmlAttribute attr, String localName, String? namespace) {
  final name = attr.name;
  return name.local == localName &&
      (name.namespaceUri == namespace || namespace == null);
}

bool _attrEqualsImplicitly(
    XmlAttribute attr, String localName, String? namespace, XmlElement node) {
  final name = attr.name;
  return name.local == localName &&
      ((name.namespaceUri == null && node.name.namespaceUri == namespace) ||
          namespace == null);
}

const _xmlSpecialToEncodedAttribute = {
  '&': '&amp;',
  '<': '&lt;',
  '"': '&quot;',
  '\r': '&#xD;',
  '\n': '&#xA;',
  '\t': '&#x9;'
};

const _xmlSpecialToEncodedText = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '\r': '&#xD;'
};

String encodeSpecialCharactersInAttribute(String attributeValue) =>
    attributeValue.replaceAllMapped(
        RegExp(r'([&<"\r\n\t])'), (m) => _xmlSpecialToEncodedAttribute[m[1]]!);

String encodeSpecialCharactersInText(String text) => text.replaceAllMapped(
    RegExp(r'([&<>\r])'), (m) => _xmlSpecialToEncodedText[m[1]]!);

XmlDocument parseFromString(String xml) =>
    XmlDocument.parse(normalizeLinebreaks(xml));

String normalizeLinebreaks(String xml) =>
    xml.replaceAll(RegExp(r'\r\n'), '\n').replaceAll(RegExp(r'\r'), '\n');

/// Normalizes a Base64-encoded RSA signature to the expected modulus width.
///
/// An RSA-PKCS#1 signature must be exactly `ceil(modulus.bitLength / 8)` bytes
/// long.  Some implementations (e.g. the ninja library) may serialize the raw
/// RSA result [BigInt] without left-padding, dropping leading `0x00` bytes when
/// the integer value happens to be smaller than the modulus.  This produces a
/// signature that is one (or more) bytes too short and fails XMLDSig
/// wire-format validation on the receiving end.
///
/// This function decodes [base64Sig], left-pads the byte array with `0x00`
/// bytes when its length is less than the expected modulus width, and returns
/// the corrected Base64 string.  A correctly-sized signature is returned
/// unchanged.  A signature that is *longer* than the modulus width indicates a
/// serious upstream error and causes a [StateError] to be thrown.
String normalizeRsaSignatureBase64(String base64Sig, BigInt modulus) {
  final expectedLen = (modulus.bitLength + 7) ~/ 8;
  final sigBytes = base64Decode(base64Sig);

  if (sigBytes.length == expectedLen) return base64Sig;

  if (sigBytes.length > expectedLen) {
    throw StateError(
        'RSA signature is ${sigBytes.length} bytes but modulus requires '
        '$expectedLen bytes');
  }

  // Left-pad with 0x00 bytes to reach the expected modulus width.
  final padded = Uint8List(expectedLen)
    ..setRange(expectedLen - sigBytes.length, expectedLen, sigBytes);
  return base64Encode(padded);
}
