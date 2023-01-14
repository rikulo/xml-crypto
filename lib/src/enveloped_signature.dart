//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 17:09:36 CST 2022
// Author: rudyhuang

import 'package:xml/xml.dart';
import 'package:xpath_selector_xml_parser/xpath_selector_xml_parser.dart';

import 'signed_xml.dart';
import 'utils.dart';

class EnvelopedSignature implements CanonicalizationAlgorithm<XmlNode> {
  @override
  String get algorithmName =>
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

  @override
  XmlNode process(XmlNode node, [Map<String, dynamic> options = const {}]) {
    final signatureNode = options['signatureNode'];
    if (signatureNode == null) {
      // leave this for the moment...
      final signature = XmlXPath.node(node).query(
          './*[local-name()="Signature""]'); // FIXME: namespace-uri() not supported
      // .query('./*[local-name()="Signature" and namespace-uri()="http://www.w3.org/2000/09/xmldsig#"]');
      final signatureNode = signature.node;
      if (signatureNode != null) {
        final child = signatureNode.node;
        child.parent?.children.remove(child);
      }
      return node;
    }

    assert(signatureNode is XmlElement);
    final expectedSignatureValue = findFirst(signatureNode as XmlElement,
            ".//*[local-name()='SignatureValue']/text()")
        .text;
    final signatures = XmlXPath.node(node).query(
        './/*[local-name()="Signature"]'); // FIXME: namespace-uri() not supported
    // .query('.//*[local-name()="Signature" and namespace-uri()="http://www.w3.org/2000/09/xmldsig#"]');
    for (final sig in signatures.nodes) {
      final child = sig.node;
      assert(child is XmlElement);
      final signatureValue = findFirst(
              child as XmlElement, ".//*[local-name()='SignatureValue']/text()")
          .text;
      if (expectedSignatureValue == signatureValue) {
        child.parent?.children.remove(child);
      }
    }

    return node;
  }
}
