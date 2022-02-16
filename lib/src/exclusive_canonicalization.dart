//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 16:08:31 CST 2022
// Author: rudyhuang

import 'package:xml/xml.dart';

import 'c14n_canonicalization.dart';
import 'utils.dart';

class ExclusiveCanonicalization extends C14nCanonicalization {
  @override
  final includeComments = false;

  @override
  String get algorithmName => 'http://www.w3.org/2001/10/xml-exc-c14n#';

  bool isPrefixInScope(List<XmlNamespace> prefixesInScope, String prefix, String? namespaceURI) {
    var ret = false;
    for (final pf in prefixesInScope) {
      if (pf.prefix == prefix && pf.namespaceURI == namespaceURI) {
        ret = true;
        break;
      }
    }
    return ret;
  }

  RenderNsResult _renderNs(XmlElement node, List<XmlNamespace> prefixesInScope, String defaultNs,
      Map<String, String> defaultNsForPrefix, List<String> inclusiveNamespacesPrefixList) {
    final res = <String>[];
    var newDefaultNs = defaultNs;
    final currNs = node.name.namespaceUri ?? '';
    final nsListToRender = <XmlNamespace>[];

    //handle the namespaceof the node itself
    final prefix = node.name.prefix;
    if (prefix != null) {
      if (!isPrefixInScope(prefixesInScope, prefix, node.name.namespaceUri ?? defaultNsForPrefix[prefix])) {
        final ns = XmlNamespace(prefix, node.name.namespaceUri ?? defaultNsForPrefix[prefix]);
        nsListToRender.add(ns);
        prefixesInScope.add(ns);
      }
    } else if (defaultNs != currNs) {
      //new default ns
      newDefaultNs = node.name.namespaceUri ?? '';
      res.add(' xmlns="$newDefaultNs"');
    }

    //handle the attributes namespace
    for (final attr in node.attributes) {
      final prefix = attr.name.prefix;
      if (prefix == null) continue;

      //handle all prefixed attributes that are included in the prefix list and where
      //the prefix is not defined already
      if (!isPrefixInScope(prefixesInScope, attr.name.local, attr.value)
          && inclusiveNamespacesPrefixList.contains(attr.name.local)) {
        final ns = XmlNamespace(attr.name.local, attr.value);
        nsListToRender.add(ns);
        prefixesInScope.add(ns);
      }

      //handle all prefixed attributes that are not xmlns definitions and where
      //the prefix is not defined already
      if (!isPrefixInScope(prefixesInScope, prefix, attr.name.namespaceUri) && prefix != "xmlns" && prefix != "xml") {
        final ns = XmlNamespace(prefix, attr.name.namespaceUri);
        nsListToRender.add(ns);
        prefixesInScope.add(ns);
      }
    }

    nsListToRender.sort(nsCompare);

    //render namespaces
    for (final ns in nsListToRender) {
      res.add(' xmlns:${ns.prefix}="${ns.namespaceURI}"');
    }

    return RenderNsResult(res.join(''), newDefaultNs);
  }

  String _processInner(XmlNode node, List<XmlNamespace> prefixesInScope, String defaultNs,
      Map<String, String> defaultNsForPrefix, List<String> inclusiveNamespacesPrefixList) {
    if (node.nodeType == XmlNodeType.COMMENT) {
      return renderComment(node);
    }

    if (xmlData.contains(node.nodeType)) {
      return encodeSpecialCharactersInText(node.text);
    }

    if (node is XmlElement) {
      final tagName = node.name.qualified,
          ns = _renderNs(node, prefixesInScope, defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList),
          res = ['<', tagName, ns.rendered, renderAttrs(node, ns.newDefaultNs), '>'];

      for (final child in node.children) {
        final pfxCopy = prefixesInScope.toList();
        res.add(_processInner(child, pfxCopy, ns.newDefaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList));
      }

      res.add('</$tagName>');
      return res.join('');
    }
    return '';
  }

  @override
  String process(XmlNode node, [Map<String, dynamic> options = const {}]) {
    var inclusiveNamespacesPrefixList = options['inclusiveNamespacesPrefixList'] ?? <String>[];
    final defaultNs = options['defaultNs'] as String? ?? '';
    final defaultNsForPrefix = options['defaultNsForPrefix'] as Map<String, String>? ?? {};
    if (inclusiveNamespacesPrefixList is String) {
      inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList.split(' ');
    }
    final ancestorNamespaces = options['ancestorNamespaces'] as List<XmlNamespace>? ?? [];

    /**
     * If the inclusiveNamespacesPrefixList has not been explicitly provided then look it up in CanonicalizationMethod/InclusiveNamespaces
     */
    if (inclusiveNamespacesPrefixList.isEmpty) {
      final canonicalizationMethod = findChilds(node, 'CanonicalizationMethod');
      if (canonicalizationMethod.isNotEmpty) {
        final inclusiveNamespaces = findChilds(canonicalizationMethod[0], 'InclusiveNamespaces');
        if (inclusiveNamespaces.isNotEmpty) {
          inclusiveNamespacesPrefixList = inclusiveNamespaces[0].getAttribute('PrefixList')?.split(' ');
        }
      }
    }

    /**
     * If you have a PrefixList then use it and the ancestors to add the necessary namespaces
     */
    if (inclusiveNamespacesPrefixList != null) {
      final prefixList = inclusiveNamespacesPrefixList is List
          ? inclusiveNamespacesPrefixList : inclusiveNamespacesPrefixList.split(' ');
      for (String prefix in prefixList) {
        for (final ancestorNamespace in ancestorNamespaces) {
          if (prefix == ancestorNamespace.prefix) {
            node.setAttribute('xmlns:' + prefix, ancestorNamespace.namespaceURI,
                namespace: 'http://www.w3.org/2000/xmlns/');
          }
        }
      }
    }

    return _processInner(node, <XmlNamespace>[], defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList);
  }
}

class ExclusiveCanonicalizationWithComments extends ExclusiveCanonicalization {
  @override
  bool get includeComments => true;

  @override
  String get algorithmName => 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
}
