//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 17:09:36 CST 2022
// Author: rudyhuang

import 'package:xml/xml.dart';

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
      final signatures = findChilds(node, 'Signature', xmlDsigNamespace);
      if (signatures.isNotEmpty) {
        final signature = signatures.first;
        signature.parent?.children.remove(signature);
      }
      return node;
    }

    assert(signatureNode is XmlElement);
    final expectedSignatureValue = findChilds(
      signatureNode as XmlElement,
      'SignatureValue',
      xmlDsigNamespace,
    ).first.innerText;
    final signatures = node.descendants.whereType<XmlElement>().where(
      (element) =>
          element.name.local == 'Signature' &&
          element.name.namespaceUri == xmlDsigNamespace,
    );
    for (final child in signatures) {
      final signatureValue = findChilds(
        child,
        'SignatureValue',
        xmlDsigNamespace,
      ).first.innerText;
      if (expectedSignatureValue == signatureValue) {
        child.parent?.children.remove(child);
      }
    }

    return node;
  }
}
