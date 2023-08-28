//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 10:18:15 CST 2022
// Author: rudyhuang

import 'package:xml/xml.dart';

import 'signed_xml.dart';
import 'utils.dart';

const xmlData = [
  XmlNodeType.CDATA,
  XmlNodeType.DOCUMENT_TYPE,
  XmlNodeType.PROCESSING,
  XmlNodeType.TEXT
];

class XmlNamespace {
  final String prefix;
  final String? namespaceURI;

  const XmlNamespace(this.prefix, this.namespaceURI);

  @override
  String toString() => '$prefix:$namespaceURI';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is XmlNamespace &&
          runtimeType == other.runtimeType &&
          prefix == other.prefix &&
          namespaceURI == other.namespaceURI;

  @override
  int get hashCode => prefix.hashCode ^ namespaceURI.hashCode;
}

class RenderNsResult {
  final String rendered;
  final String newDefaultNs;

  RenderNsResult(this.rendered, this.newDefaultNs);
}

class C14nCanonicalization implements CanonicalizationAlgorithm<String> {
  bool get includeComments => false;

  int attrCompare(XmlAttribute a, XmlAttribute b) {
    // workaround: protocolSupportEnumeration namespaceUri should be null, not `urn:...` so use prefix to compare
    if (a.name.prefix == null && b.name.prefix != null) return -1;
    if (b.name.prefix == null && a.name.prefix != null) return 1;

    final left = (a.name.namespaceUri ?? '') + a.name.local;
    final right = (b.name.namespaceUri ?? '') + b.name.local;

    return left.compareTo(right);
  }

  int nsCompare(XmlNamespace a, XmlNamespace b) {
    final attr1 = a.prefix, attr2 = b.prefix;
    if (attr1 == attr2) return 0;
    return attr1.compareTo(attr2);
  }

  String renderAttrs(XmlNode node, String defaultNS) {
    if (node.nodeType == XmlNodeType.COMMENT) {
      return renderComment(node);
    }

    final attrs = node.attributes;
    final attrListToRender = <XmlAttribute>[];
    for (final attr in attrs) {
      //ignore namespace definition attributes
      if (attr.name.qualified.startsWith('xmlns')) continue;
      attrListToRender.add(attr);
    }

    attrListToRender.sort(attrCompare);

    return attrListToRender
        .map((attr) =>
            ' ${attr.name.qualified}="${encodeSpecialCharactersInAttribute(attr.value)}"')
        .join('');
  }

  RenderNsResult _renderNs(
      XmlElement node,
      List<String> prefixesInScope,
      String defaultNs,
      Map<String, String> defaultNsForPrefix,
      List<XmlNamespace> ancestorNamespaces) {
    final res = <String>[];
    var newDefaultNs = defaultNs;
    final currNs = node.name.namespaceUri ?? '';
    final nsListToRender = <XmlNamespace>[];

    //handle the namespaceof the node itself
    final prefix = node.name.prefix;
    if (prefix != null) {
      if (!prefixesInScope.contains(prefix)) {
        nsListToRender.add(XmlNamespace(
            prefix, node.name.namespaceUri ?? defaultNsForPrefix[prefix]));
        prefixesInScope.add(prefix);
      }
    } else if (defaultNs != currNs) {
      //new default ns
      newDefaultNs = node.name.namespaceUri ?? '';
      res.add(' xmlns="$newDefaultNs"');
    }

    //handle the attributes namespace
    for (final attr in node.attributes) {
      final prefix = attr.name.prefix;

      //handle all prefixed attributes that are included in the prefix list and where
      //the prefix is not defined already. New prefixes can only be defined by `xmlns:`.
      if (prefix == 'xmlns' && !prefixesInScope.contains(attr.name.local)) {
        nsListToRender.add(XmlNamespace(attr.name.local, attr.value));
        prefixesInScope.add(attr.name.local);
      }

      //handle all prefixed attributes that are not xmlns definitions and where
      //the prefix is not defined already
      if (prefix != null &&
          !prefixesInScope.contains(prefix) &&
          prefix != 'xmlns' &&
          prefix != 'xml') {
        nsListToRender.add(XmlNamespace(prefix, attr.name.namespaceUri));
        prefixesInScope.add(prefix);
      }
    }

    // Remove namespaces which are already present in nsListToRender
    for (final p1 in ancestorNamespaces) {
      var alreadyListed = false;
      for (final p2 in nsListToRender) {
        if (p2 == p1) {
          alreadyListed = true;
        }
      }

      if (!alreadyListed) {
        nsListToRender.add(p1);
      }
    }

    nsListToRender.sort(nsCompare);

    //render namespaces
    for (final ns in nsListToRender) {
      res.add(' xmlns${ns.prefix.isNotEmpty ? ':${ns.prefix}' : ''}="${ns.namespaceURI}"');
    }

    return RenderNsResult(res.join(''), newDefaultNs);
  }

  String _processInner(
      XmlNode node,
      List<String> prefixesInScope,
      String defaultNs,
      Map<String, String> defaultNsForPrefix,
      List<XmlNamespace> ancestorNamespaces) {
    if (node.nodeType == XmlNodeType.COMMENT) {
      return renderComment(node);
    }

    if (xmlData.contains(node.nodeType)) {
      return encodeSpecialCharactersInText(node.text);
    }

    if (node is XmlElement) {
      final tagName = node.name.qualified,
          ns = _renderNs(node, prefixesInScope, defaultNs, defaultNsForPrefix,
              ancestorNamespaces),
          res = [
            '<',
            tagName,
            ns.rendered,
            renderAttrs(node, ns.newDefaultNs),
            '>'
          ];

      for (final child in node.children) {
        final pfxCopy = prefixesInScope.toList();
        res.add(_processInner(child, pfxCopy, ns.newDefaultNs,
            defaultNsForPrefix, <XmlNamespace>[]));
      }

      res.add('</$tagName>');
      return res.join('');
    }
    return '';
  }

  // Thanks to deoxxa/xml-c14n for comment renderer
  String renderComment(XmlNode node) {
    if (!includeComments) return '';

    var isOutsideDocument = (node.document == node.parent),
        isBeforeDocument = false,
        isAfterDocument = false;

    if (isOutsideDocument) {
      XmlNode? nextNode = node, previousNode = node;

      while (nextNode != null) {
        if (nextNode == node.document?.rootElement) {
          isBeforeDocument = true;
          break;
        }

        nextNode = nextNode.nextSibling;
      }

      while (previousNode != null) {
        if (previousNode == node.document?.rootElement) {
          isAfterDocument = true;
          break;
        }

        previousNode = previousNode.previousSibling;
      }
    }

    return '${isAfterDocument ? '\n' : ''}<!--${encodeSpecialCharactersInText(node.text)}-->${isBeforeDocument ? '\n' : ''}';
  }

  @override
  String process(XmlNode node, [Map<String, dynamic> options = const {}]) {
    final defaultNs = options['defaultNs'] as String? ?? '';
    final defaultNsForPrefix =
        options['defaultNsForPrefix'] as Map<String, String>? ?? {};
    final ancestorNamespaces =
        options['ancestorNamespaces'] as List<XmlNamespace>? ?? [];

    final prefixesInScope = <String>[];
    for (var i = 0; i < ancestorNamespaces.length; i++) {
      prefixesInScope.add(ancestorNamespaces[i].prefix);
    }

    return _processInner(node, prefixesInScope, defaultNs, defaultNsForPrefix,
        ancestorNamespaces);
  }

  @override
  String get algorithmName => 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
}

class C14nCanonicalizationWithComments extends C14nCanonicalization {
  @override
  bool get includeComments => true;

  @override
  String get algorithmName =>
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
}
