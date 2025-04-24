//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Tue Feb 08 17:32:30 CST 2022
// Author: rudyhuang

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';
import 'package:ninja/ninja.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart' show RSAPKCSParser;
import 'package:xml/xml.dart';
import 'package:xpath_selector/xpath_selector.dart';
import 'package:xpath_selector_xml_parser/xpath_selector_xml_parser.dart';

import 'c14n_canonicalization.dart';
import 'enveloped_signature.dart';
import 'exclusive_canonicalization.dart';
import 'utils.dart';

typedef CalculateSignatureCallback = void Function(
    Error? e, String signatureValue);
typedef ValidateSignatureCallback = void Function(Error? e, bool valid);
typedef ComputeSignatureCallback = void Function(Error? e, SignedXml? instance);

List<XmlNamespace> findAncestorNs(XmlDocument doc, String docSubsetXpath,
    [namespaceResolver]) {
  final docSubset = XmlXPath.node(doc)
      .query(docSubsetXpath); // FIXME: supports namespaceResolver
  final result = docSubset.node;
  if (result == null) {
    return [];
  }

  final node = result.node;
  final ancestorNs = _collectAncestorNamespaces(node);
  final ancestorNsWithoutDuplicate = <XmlNamespace>[];
  for (final ns in ancestorNs) {
    var notOnTheList = true;

    for (final ns2 in ancestorNsWithoutDuplicate) {
      if (ns2.prefix == ns.prefix) {
        notOnTheList = false;
        break;
      }
    }

    if (notOnTheList) {
      ancestorNsWithoutDuplicate.add(ns);
    }
  }

  final returningNs = <XmlNamespace>[];
  final subsetNsPrefix = _findNSPrefix(node);
  for (var ancestorNs in ancestorNsWithoutDuplicate) {
    if (ancestorNs.prefix != subsetNsPrefix) {
      returningNs.add(ancestorNs);
    }
  }

  return returningNs;
}

String _findNSPrefix(XmlNode subset) {
  final subsetAttributes = subset.attributes;
  final regexp = RegExp(r'^xmlns:?');
  for (var attr in subsetAttributes) {
    final nodeName = attr.qualifiedName;
    if (nodeName.startsWith(regexp)) {
      return nodeName.replaceAll(regexp, '');
    }
  }
  return subset is XmlElement ? (subset.namespacePrefix ?? '') : '';
}

List<XmlNamespace> _collectAncestorNamespaces(XmlNode node,
    [List<XmlNamespace>? nsArray]) {
  nsArray ??= [];

  var parent = node.parent;
  if (parent == null) {
    return nsArray;
  }

  final regexp = RegExp(r'^xmlns:?');
  for (var attr in parent.attributes) {
    final name = attr.name.qualified;
    if (name.startsWith(regexp)) {
      nsArray.add(XmlNamespace(name.replaceFirst(regexp, ''), attr.value));
    }
  }

  return _collectAncestorNamespaces(parent, nsArray);
}

class SignedXml {
  static final Map<String, CanonicalizationAlgorithm>
      canonicalizationAlgorithms = {
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315': C14nCanonicalization(),
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
        C14nCanonicalizationWithComments(),
    'http://www.w3.org/2001/10/xml-exc-c14n#': ExclusiveCanonicalization(),
    'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
        ExclusiveCanonicalizationWithComments(),
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature':
        EnvelopedSignature(),
  };

  static final Map<String, HashAlgorithm> hashAlgorithms = {
    'http://www.w3.org/2000/09/xmldsig#sha1': SHA1(),
    'http://www.w3.org/2001/04/xmlenc#sha256': SHA256(),
    'http://www.w3.org/2001/04/xmlenc#sha512': SHA512(),
  };

  static final Map<String, SignatureAlgorithm> signatureAlgorithms = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': RSASHA1(),
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': RSASHA256(),
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': RSASHA512(),
    // Disabled by default due to key confusion concerns.
    // 'http://www.w3.org/2000/09/xmldsig#hmac-sha1': HMACSHA1,
  };

  static final Map<String, String> defaultNsForPrefix = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
  };

  final Map<String, dynamic> options;
  final String idMode;
  final references = <_Reference>[];
  var _id = 0;
  Uint8List? signingKey;
  Uint8List? signingCert;
  late String signatureAlgorithm;
  KeyInfoProvider? _keyInfoProvider;
  late String canonicalizationAlgorithm;
  late String inclusiveNamespacesPrefixList;
  String _signedXml = '';
  String _signatureXml = '';
  XmlNode? _signatureNode;
  String signatureValue = '';
  String _originalXmlWithIds = '';
  final validationErrors = <String>[];
  String? keyInfo;
  final idAttributes = ['Id', 'ID', 'id'];
  late List<String> implicitTransforms;
  final customSignatureChilds = <String>[];

  /// Xml signature implementation
  ///
  /// [idMode]. Value of "wssecurity" will create/validate id's with the ws-security namespace
  /// [options]. Initial configurations
  SignedXml([this.idMode = '', this.options = const {}]) {
    signatureAlgorithm = options['signatureAlgorithm'] as String? ??
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    canonicalizationAlgorithm =
        options['canonicalizationAlgorithm'] as String? ??
            'http://www.w3.org/2001/10/xml-exc-c14n#';
    inclusiveNamespacesPrefixList =
        options['inclusiveNamespacesPrefixList'] as String? ?? '';

    final idAttribute = options['idAttribute'];
    if (idAttribute is List<String>) idAttributes.insertAll(0, idAttribute);

    implicitTransforms = options['implicitTransforms'] as List<String>? ?? [];
  }

  /// Due to key-confusion issues, its risky to have both hmac
  /// and digital signature algos enabled at the same time.
  /// This enables HMAC and disables other signing algos.
  static void enableHMAC() {
    signatureAlgorithms
      ..clear()
      ..addAll({'http://www.w3.org/2000/09/xmldsig#hmac-sha1': HMACSHA1()});
  }

  bool checkSignature(String xml, [ValidateSignatureCallback? callback]) {
    validationErrors.clear();
    _signedXml = xml;

    if (keyInfoProvider == null) {
      final err = ArgumentError(
          'cannot validate signature since no key info resolver was provided');
      if (callback == null) {
        throw err;
      } else {
        callback(err, false);
        return false;
      }
    }

    signingKey = keyInfoProvider!.getKey(keyInfo);
    if (signingKey == null) {
      final err = ArgumentError(
          'key info provider could not resolve key info $keyInfo');
      if (callback == null) {
        throw err;
      } else {
        callback(err, false);
        return false;
      }
    }

    final doc = parseFromString(xml);

    // Reset the references as only references from our re-parsed signedInfo node can be trusted
    this.references.clear();

    final unverifiedSignedInfoCanon = _getCanonSignedInfoXml(doc);
    if (unverifiedSignedInfoCanon.isEmpty) {
      if (callback != null) {
        callback(ArgumentError('Canonical signed info cannot be empty'), false);
        return false;
      }

      throw ArgumentError('Canonical signed info cannot be empty');
    }

    // unsigned, verify later to keep with consistent callback behavior
    final parsedUnverifiedSignedInfo =
        parseFromString(unverifiedSignedInfoCanon);
    final unverifiedSignedInfoDoc = parsedUnverifiedSignedInfo.document;
    if (unverifiedSignedInfoDoc == null) {
      if (callback != null) {
        callback(
            ArgumentError('Could not parse signedInfoCanon into a document'),
            false);
        return false;
      }

      throw ArgumentError('Could not parse signedInfoCanon into a document');
    }

    final references = findChilds(unverifiedSignedInfoDoc, 'Reference');
    if (references.isEmpty) {
      if (callback != null) {
        callback(ArgumentError('could not find any Reference elements'), false);
        return false;
      }

      throw ArgumentError('could not find any Reference elements');
    }

    for (var reference in references) {
      _loadReference(reference);
    }

    if (!_validateReferences(doc)) {
      if (callback == null) {
        return false;
      } else {
        callback(ArgumentError('Could not validate references'), false);
        return false;
      }
    }

    // Stage B: Take the signature algorithm and key and verify the SignatureValue against the canonicalized SignedInfo
    if (callback == null) {
      //Synchronous flow
      if (!_validateSignatureValue(doc)) {
        return false;
      }
      return true;
    } else {
      //Asynchronous flow
      _validateSignatureValue(doc, (Error? err, bool isValidSignature) {
        if (err != null) {
          validationErrors.add(
              'invalid signature: the signature value $signatureValue is incorrect');
          callback(err, false);
        } else {
          callback(null, isValidSignature);
        }
      });
      return true;
    }
  }

  String _getCanonSignedInfoXml(XmlDocument doc) {
    final signedInfo = findChilds(_signatureNode!, 'SignedInfo');
    if (signedInfo.isEmpty) {
      throw ArgumentError('could not find SignedInfo element in the message');
    }
    if (signedInfo.length > 1) {
      throw ArgumentError(
          'could not get canonicalized signed info for a signature that contains multiple SignedInfo nodes');
    }

    // Since in Dart the doc is always a XmlDocument
    // if (canonicalizationAlgorithm == 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    //   || canonicalizationAlgorithm == 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments') {
    //   if (!doc || typeof(doc) !== "object") {
    //      throw new Error('When canonicalization method is non-exclusive, whole xml dom must be provided as an argument');
    //   }
    // }

    // Search for ancestor namespaces before canonicalization.
    final ancestorNamespaces =
        findAncestorNs(doc, "//*[local-name()='SignedInfo']");
    final c14nOptions = <String, dynamic>{
      'ancestorNamespaces': ancestorNamespaces,
    };
    return _getCanonXml(
        [canonicalizationAlgorithm], signedInfo.first, c14nOptions);
  }

  String _getCanonReferenceXml(XmlDocument doc, _Reference ref, XmlNode node) {
    // Search for ancestor namespaces before canonicalization.
    if (ref.transforms.isNotEmpty) {
      ref.ancestorNamespaces = findAncestorNs(doc, ref.xpath ?? '');
    }

    final c14nOptions = <String, dynamic>{
      'inclusiveNamespacesPrefixList': ref.inclusiveNamespacesPrefixList,
      'ancestorNamespaces': ref.ancestorNamespaces,
    };

    return _getCanonXml(ref.transforms, node, c14nOptions);
  }

  bool _validateSignatureValue(XmlDocument doc,
      [ValidateSignatureCallback? callback]) {
    final signedInfoCanon = _getCanonSignedInfoXml(doc);
    final signer = _findSignatureAlgorithm(signatureAlgorithm);
    final res = signer.verifySignature(
        signedInfoCanon, signingKey!, signatureValue, callback);
    if (!res && callback == null) {
      validationErrors.add(
          'invalid signature: the signature value $signatureValue is incorrect');
    }
    return res;
  }

  void _calculateSignatureValue(XmlDocument doc,
      [CalculateSignatureCallback? callback]) {
    final signedInfoCanon = _getCanonSignedInfoXml(doc);
    final signer = _findSignatureAlgorithm(signatureAlgorithm);
    signatureValue =
        signer.getSignature(signedInfoCanon, signingKey!, callback);
  }

  SignatureAlgorithm _findSignatureAlgorithm(String name) {
    final algo = signatureAlgorithms[name];
    if (algo != null) {
      return algo;
    } else {
      throw UnsupportedError('signature algorithm $name is not supported');
    }
  }

  CanonicalizationAlgorithm _findCanonicalizationAlgorithm(String name) {
    final algo = canonicalizationAlgorithms[name];
    if (algo != null) {
      return algo;
    } else {
      throw UnsupportedError(
          'canonicalization algorithm $name is not supported');
    }
  }

  HashAlgorithm _findHashAlgorithm(String name) {
    final algo = hashAlgorithms[name];
    if (algo != null) {
      return algo;
    } else {
      throw UnsupportedError('hash algorithm $name is not supported');
    }
  }

  bool _validateReferences(XmlDocument doc) {
    for (final ref in references) {
      final uri = ref.uri != null
          ? (ref.uri!.startsWith('#') ? ref.uri!.substring(1) : ref.uri!)
          : '';
      final elem = <XPathNode<XmlNode>>[];

      if (uri == '') {
        elem.addAll(XmlXPath.node(doc).query('//*').nodes);
      } else if (uri.contains('\'')) {
        // xpath injection
        throw UnsupportedError('Cannot validate a uri with quotes inside it');
      } else {
        var elemXpath = '';
        var numElementsForId = 0;
        for (final id in idAttributes) {
          final tmpElemXpath = '//*[@$id="$uri"]';
          final tmpElem = XmlXPath.node(doc).query(tmpElemXpath).nodes;
          numElementsForId += tmpElem.length;
          if (tmpElem.isNotEmpty) {
            elem
              ..clear()
              ..addAll(tmpElem);
            elemXpath = tmpElemXpath;
          }
        }
        if (numElementsForId > 1) {
          throw ArgumentError(
              'Cannot validate a document which contains multiple elements with the '
              'same value for the ID / Id / Id attributes, in order to prevent '
              'signature wrapping attack.');
        }

        ref.xpath = elemXpath;
      }

      if (elem.isEmpty) {
        validationErrors.add(
            'invalid signature: the signature references an element'
            ' with uri ${ref.uri} but could not find such element in the xml');
        return false;
      }

      final canonXml = _getCanonReferenceXml(doc, ref, elem.first.node);
      final hash = _findHashAlgorithm(ref.digestAlgorithm);
      final digest = hash.getHash(canonXml);
      if (!_validateDigestValue(digest, ref.digestValue)) {
        validationErrors.add('invalid signature: for uri ${ref.uri}'
            ' calculated digest is $digest'
            ' but the xml to validate supplies digest ${ref.digestValue}');
        return false;
      }
    }
    return true;
  }

  bool _validateDigestValue(String digest, String expectedDigest) =>
      digest.trim() == expectedDigest.trim();

  void loadSignature(dynamic signatureNode) {
    if (signatureNode is String) {
      _signatureNode =
          signatureNode = parseFromString(signatureNode).rootElement;
    } else {
      _signatureNode = signatureNode;
    }

    _signatureXml = signatureNode.toString();

    var nodes = XmlXPath.node(signatureNode)
        .query(".//*[local-name()='CanonicalizationMethod']/@Algorithm");
    if (nodes.node == null) {
      throw ArgumentError(
          'could not find CanonicalizationMethod/@Algorithm element');
    }
    canonicalizationAlgorithm = nodes.attr ?? '';
    nodes = XmlXPath.node(signatureNode)
        .query(".//*[local-name()='SignatureMethod']/@Algorithm");
    if (nodes.node == null) {
      throw ArgumentError('could not find SignatureMethod/@Algorithm element');
    }
    signatureAlgorithm = nodes.attr ?? '';
    final signedInfoNodes = findChilds(signatureNode, 'SignedInfo');
    if (signedInfoNodes.isEmpty) {
      throw ArgumentError('no signed info node found');
    }
    if (signedInfoNodes.length > 1) {
      throw ArgumentError(
          'could not load signature that contains multiple SignedInfo nodes');
    }

    // Try to operate on the c14n version of signedInfo. This forces the initial getReferences()
    // API call to always return references that are loaded under the canonical SignedInfo
    // in the case that the client access the .references **before** signature verification.

    // Ensure canonicalization algorithm is exclusive, otherwise we'd need the entire document
    var canonicalizationAlgorithmForSignedInfo = canonicalizationAlgorithm;
    if (canonicalizationAlgorithmForSignedInfo ==
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ||
        canonicalizationAlgorithmForSignedInfo ==
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments") {
      canonicalizationAlgorithmForSignedInfo =
          "http://www.w3.org/2001/10/xml-exc-c14n#";
    }

    final temporaryCanonSignedInfo = _getCanonXml(
      [canonicalizationAlgorithmForSignedInfo],
      signedInfoNodes.first,
    );
    final temporaryCanonSignedInfoXml =
        parseFromString(temporaryCanonSignedInfo);
    final signedInfoDoc = temporaryCanonSignedInfoXml.rootElement;

    this.references.clear();

    final references = findChilds(signedInfoDoc, 'Reference');
    if (references.isEmpty) {
      throw ArgumentError('could not find any Reference elements');
    }

    for (final ref in references) {
      _loadReference(ref);
    }

    signatureValue =
        findFirst(signatureNode, ".//*[local-name()='SignatureValue']/text()")
            .innerText
            .replaceAll(RegExp(r'\r?\n'), '');
    keyInfo = XmlXPath.node(signatureNode)
        .query(".//*[local-name()='KeyInfo']")
        .node
        ?.node
        .toString();
  }

  void _loadReference(XmlNode ref) {
    var nodes = findChilds(ref, 'DigestMethod');
    if (nodes.isEmpty) {
      throw ArgumentError('could not find DigestMethod in reference $ref');
    }
    final digestAlgoNode = nodes.first;

    final attr = findAttr(digestAlgoNode, 'Algorithm');
    if (attr == null) {
      throw ArgumentError(
          'could not find Algorithm attribute in node $digestAlgoNode');
    }
    final digestAlgo = attr.value;

    nodes = findChilds(ref, 'DigestValue');
    if (nodes.isEmpty) {
      throw ArgumentError('could not find DigestValue in reference $ref');
    }

    if (nodes.length > 1) {
      throw ArgumentError(
          'could not load reference for a node that contains multiple DigestValue nodes: $ref');
    }

    final digestValue = nodes.first.innerText;
    if (digestValue.isEmpty) {
      throw ArgumentError('could not find the value of DigestValue in $ref');
    }

    final transforms = <String>[];
    String? inclusiveNamespacesPrefixList;
    nodes = findChilds(ref, 'Transforms');
    if (nodes.isNotEmpty) {
      final transformsNode = nodes.first;
      final transformsAll = findChilds(transformsNode, 'Transform');
      for (final trans in transformsAll) {
        transforms.add(findAttr(trans, 'Algorithm')?.value ?? '');
      }

      final inclusiveNamespaces =
          findChilds(transformsAll.last, 'InclusiveNamespaces');
      //Should really only be one prefix list, but maybe there's some circumstances where more than one to lets handle it
      for (final inclusiveNamespace in inclusiveNamespaces) {
        if (inclusiveNamespacesPrefixList != null) {
          inclusiveNamespacesPrefixList +=
              ' ${inclusiveNamespace.getAttribute('PrefixList') ?? ''}';
        } else {
          inclusiveNamespacesPrefixList =
              inclusiveNamespace.getAttribute('PrefixList');
        }
      }
    }

    final hasImplicitTransform = implicitTransforms.isNotEmpty;
    if (hasImplicitTransform) {
      transforms.addAll(implicitTransforms);
    }

    /**
     * DigestMethods take an octet stream rather than a node set. If the output of the last transform is a node set, we
     * need to canonicalize the node set to an octet stream using non-exclusive canonicalization. If there are no
     * transforms, we need to canonicalize because URI dereferencing for a same-document reference will return a node-set.
     * See:
     * https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod
     * https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel
     * https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document
     */
    if (transforms.isEmpty ||
        transforms.last ==
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature') {
      transforms.add('http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
    }

    final refUri = ref.getAttribute('URI');
    addReference(null, transforms, digestAlgo, refUri, digestValue,
        inclusiveNamespacesPrefixList, false);
  }

  void addReference(String? xpath,
      [List<String>? transforms,
      String? digestAlgorithm,
      String? uri,
      String? digestValue,
      String? inclusiveNamespacesPrefixList,
      bool isEmptyUri = false]) {
    references.add(_Reference(
        xpath,
        transforms ?? ['http://www.w3.org/2001/10/xml-exc-c14n#'],
        digestAlgorithm ?? 'http://www.w3.org/2000/09/xmldsig#sha1',
        uri ?? '',
        digestValue ?? '',
        inclusiveNamespacesPrefixList,
        isEmptyUri));
  }

  void addCustomSignatureChild(String node) {
    customSignatureChilds.add(node);
  }

  /// Compute the signature of the given xml (using the already defined settings)
  ///
  /// Options:
  ///
  /// - `prefix` {String} Adds a prefix for the generated signature tags
  /// - `attrs` {Map<String, String>} A hash of attributes and values `attrName: value` to add to the signature root node
  /// - `location` {{ 'reference': String, 'action': String }}
  /// - `existingPrefixes` {Map<String, String>} A hash of prefixes and namespaces `prefix: namespace` already in the xml
  ///   An object with a `reference` key which should
  ///   contain a XPath expression, an `action` key which
  ///   should contain one of the following values:
  ///   `append`, `prepend`, `before`, `after`
  void computeSignature(String xml,
      {Map<String, dynamic>? opts, ComputeSignatureCallback? callback}) {
    final doc = parseFromString(xml);
    var xmlNsAttr = 'xmlns';
    final signatureAttrs = <String>[];
    var currentPrefix = '';

    final validActions = ['append', 'prepend', 'before', 'after'];

    opts = opts ?? {};
    final prefix = opts['prefix'] as String?;
    final attrs = opts['attrs'] as Map<String, String>? ?? {};
    final location = opts['location'] as Map<String, String>? ?? {};
    final existingPrefixes =
        opts['existingPrefixes'] as Map<String, String>? ?? {};

    // TODO
    // namespaceResolver = {
    //   lookupNamespaceURI: function(prefix) {
    //     return existingPrefixes[prefix];
    //   }
    // }

    // defaults to the root node
    location['reference'] = location['reference'] ?? '/*';
    // defaults to append action
    location['action'] = location['action'] ?? 'append';

    if (!validActions.contains(location['action'])) {
      final err = ArgumentError(
          'location.action option has an invalid action:  ${location['action']},'
          'must be any of the following values: ${validActions.join(', ')}');
      if (callback == null) {
        throw err;
      } else {
        callback(err, null);
        return;
      }
    }

    // automatic insertion of `:`
    if (prefix != null && prefix.isNotEmpty) {
      xmlNsAttr += ':$prefix';
      currentPrefix = '$prefix:';
    } else {
      currentPrefix = '';
    }

    for (final entry in attrs.entries) {
      final name = entry.key;
      if (name != 'xmlns' && name != xmlNsAttr) {
        signatureAttrs.add('$name="${entry.value}"');
      }
    }

    // add the xml namespace attribute
    signatureAttrs.add('$xmlNsAttr="http://www.w3.org/2000/09/xmldsig#"');

    final signatureXml =
        StringBuffer('<${currentPrefix}Signature ${signatureAttrs.join(' ')}>')
          ..write(_createSignedInfo(doc, prefix))
          ..write(_getKeyInfo(prefix))
          ..write(customSignatureChilds.join(''))
          ..write('</${currentPrefix}Signature>');

    _originalXmlWithIds = doc.toString();

    var existingPrefixesString = '';
    for (final entry in existingPrefixes.entries) {
      existingPrefixesString += 'xmlns:${entry.key}="${entry.value}" ';
    }

    // A trick to remove the namespaces that already exist in the xml
    // This only works if the prefix and namespace match with those in te xml
    final dummySignatureWrapper =
        '<Dummy $existingPrefixesString>$signatureXml</Dummy>';
    final xml2 = parseFromString(dummySignatureWrapper);
    final signatureDoc = xml2.rootElement.firstChild!.copy();

    final referenceNodeQuery = XmlXPath.node(doc).query(location['reference']!);
    if (referenceNodeQuery.nodes.isEmpty) {
      final err = ArgumentError(
          'the following xpath cannot be used because it was not found: ${location['reference']}');
      if (callback == null) {
        throw err;
      } else {
        callback(err, null);
        return;
      }
    }

    final referenceNode = referenceNodeQuery.node!.node;

    if (location['action'] == 'append') {
      referenceNode.children.add(signatureDoc);
    } else if (location['action'] == 'prepend') {
      referenceNode.children.insert(0, signatureDoc);
    } else if (location['action'] == 'before') {
      final ch = referenceNode.parent?.children;
      if (ch != null) ch.insert(ch.indexOf(referenceNode), signatureDoc);
    } else if (location['action'] == 'after') {
      final ch = referenceNode.parent?.children;
      if (ch != null) {
        final indexOf = ch.indexOf(referenceNode) + 1;
        if (indexOf < ch.length) {
          ch.insert(indexOf, signatureDoc);
        } else {
          ch.add(signatureDoc);
        }
      }
    }

    _signatureNode = signatureDoc;
    final signedInfoNodeQuery = findChilds(_signatureNode!, 'SignedInfo');
    if (signedInfoNodeQuery.isEmpty) {
      final err =
          ArgumentError('could not find SignedInfo element in the message');
      if (callback == null) {
        throw err;
      } else {
        callback(err, null);
        return;
      }
    }
    final signedInfoNode = signedInfoNodeQuery.first;

    if (callback == null) {
      //Synchronous flow
      _calculateSignatureValue(doc);
      final ch = signedInfoNode.parent?.children;
      if (ch != null) {
        final index = ch.indexOf(signedInfoNode) + 1;
        if (index < ch.length) {
          ch.insert(index, _createSignature(prefix));
        } else {
          ch.add(_createSignature(prefix));
        }
      }
      _signatureXml = signatureDoc.toString();
      _signedXml = doc.toString();
    } else {
      //Asynchronous flow
      _calculateSignatureValue(doc, (err, signatureValue) {
        if (err != null) {
          callback(err, null);
          return;
        }
        this.signatureValue = signatureValue;
        final ch = signedInfoNode.parent?.children;
        if (ch != null) {
          final index = ch.indexOf(signedInfoNode) + 1;
          if (index < ch.length) {
            ch.insert(index, _createSignature(prefix));
          } else {
            ch.add(_createSignature(prefix));
          }
        }
        _signatureXml = signatureDoc.toString();
        _signedXml = doc.toString();
        callback(null, this);
      });
    }
  }

  String _getKeyInfo(String? prefix) {
    final res = StringBuffer();
    var currentPrefix = prefix ?? '';
    if (currentPrefix.isNotEmpty) currentPrefix += ':';

    if (keyInfoProvider != null) {
      final keyInfoAttrs = StringBuffer(), attrs = keyInfoProvider!.attrs;
      if (attrs != null) {
        for (var entry in attrs.entries) {
          keyInfoAttrs.write(' ${entry.key}="${entry.value}"');
        }
      }
      res
        ..write('<${currentPrefix}KeyInfo${keyInfoAttrs.toString()}>')
        ..write(keyInfoProvider!.getKeyInfo(signingCert ?? signingKey, prefix))
        ..write('</${currentPrefix}KeyInfo>');
    }
    return res.toString();
  }

  /// Generate the Reference nodes (as part of the signature process)
  String _createReference(XmlDocument doc, String? prefix) {
    final res = StringBuffer();

    prefix = prefix ?? '';
    prefix = prefix.isNotEmpty ? '$prefix:' : prefix;

    for (final ref in references) {
      final nodes = XmlXPath.node(doc).query(ref.xpath ?? '');
      if (nodes.nodes.isEmpty) {
        //Search if the xpath is in customSignatureChilds
        for (final customSignatureChild in customSignatureChilds) {
          final customSignatureChildXml = parseFromString(customSignatureChild);
          final customSignatureChildQuery = XmlXPath.node(customSignatureChildXml).query(ref.xpath ?? '');
          if (customSignatureChildQuery.nodes.isNotEmpty) {
            nodes.nodes.add(customSignatureChildQuery.node!);
          } 
        }

        if (nodes.nodes.isEmpty) {
          throw ArgumentError('the following xpath cannot be signed because it was not found: ${ref.xpath}');
        }
      }

      for (final node in nodes.nodes) {
        if (ref.isEmptyUri) {
          res.write('<${prefix}Reference URI="">');
        } else {
          final id = _ensureHasId(node.node);
          ref.uri = id;
          res.write('<${prefix}Reference URI="#$id">');
        }
        res.write('<${prefix}Transforms>');
        for (final trans in ref.transforms) {
          final transform = _findCanonicalizationAlgorithm(trans);
          res.write(
              '<${prefix}Transform Algorithm="${transform.algorithmName}"');
          final prefixList = ref.inclusiveNamespacesPrefixList;
          if (prefixList?.isNotEmpty == true) {
            res
              ..write('>')
              ..write(
                  '<InclusiveNamespaces PrefixList="$prefixList" xmlns="${transform.algorithmName}"/>')
              ..write('</${prefix}Transform>');
          } else {
            res.write(' />');
          }
        }

        final canonXml = _getCanonReferenceXml(doc, ref, node.node);
        final digestAlgorithm = _findHashAlgorithm(ref.digestAlgorithm);
        res
          ..write('</${prefix}Transforms>')
          ..write(
              '<${prefix}DigestMethod Algorithm="${digestAlgorithm.algorithmName}" />')
          ..write(
              '<${prefix}DigestValue>${digestAlgorithm.getHash(canonXml)}</${prefix}DigestValue>')
          ..write('</${prefix}Reference>');
      }
    }
    return res.toString();
  }

  String _getCanonXml(List<String> transforms, XmlNode node,
      [Map<String, dynamic>? options]) {
    options = options ?? {};
    if (options['defaultNsForPrefix'] == null) {
      options['defaultNsForPrefix'] = defaultNsForPrefix;
    }
    options['signatureNode'] = _signatureNode;

    dynamic canonXml = node.copy(); // Deep clone
    // Workaround: XmlPrefixName.namespaceUri will look up the namespace from the parent node
    if (canonXml is XmlNode && node.hasParent) {
      // ignore: invalid_use_of_internal_member
      canonXml.attachParent(node.parent!);
    }
    for (final t in transforms) {
      final transform = _findCanonicalizationAlgorithm(t);
      canonXml = transform.process(canonXml, options);
      //TODO: currently transform.process may return either Node or String value (enveloped transformation returns Node, exclusive-canonicalization returns String).
      //This either needs to be more explicit in the API, or all should return the same.
      //exclusive-canonicalization returns String since it builds the Xml by hand. If it had used xmldom it would inccorectly minimize empty tags
      //to <x/> instead of <x></x> and also incorrectly handle some delicate line break issues.
      //enveloped transformation returns Node since if it would return String consider this case:
      //<x xmlns:p='ns'><p:y/></x>
      //if only y is the node to sign then a string would be <p:y/> without the definition of the p namespace. probably xmldom toString() should have added it.
    }
    return canonXml.toString();
  }

  String _ensureHasId(XmlNode node) {
    XmlAttribute? attr;
    if (idMode == 'wssecurity') {
      attr = findAttr(node, 'Id',
          'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
    } else {
      for (final id in idAttributes) {
        attr = findAttr(node, id);
        if (attr != null) break;
      }
    }

    if (attr != null) return attr.value;

    //add the attribute
    final id = '_${_id++}';

    if (idMode == 'wssecurity') {
      node.setAttribute('xmlns:wsu',
          'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
          namespace: 'http://www.w3.org/2000/xmlns/');
      node.setAttribute('wsu:Id', id,
          namespace:
              'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
    } else {
      node.setAttribute('Id', id);
    }

    return id;
  }

  /// Create the SignedInfo element
  String _createSignedInfo(XmlDocument doc, String? prefix) {
    final transform = _findCanonicalizationAlgorithm(canonicalizationAlgorithm);
    final algo = _findSignatureAlgorithm(signatureAlgorithm);
    var currentPrefix = prefix ?? '';
    currentPrefix = currentPrefix.isNotEmpty ? '$currentPrefix:' : '';

    final res = StringBuffer('<${currentPrefix}SignedInfo>')
      ..write(
          '<${currentPrefix}CanonicalizationMethod Algorithm="${transform.algorithmName}"');
    if (inclusiveNamespacesPrefixList.isNotEmpty) {
      res
        ..write('>')
        ..write(
            '<InclusiveNamespaces PrefixList="$inclusiveNamespacesPrefixList" xmlns="${transform.algorithmName}"/>')
        ..write('</${currentPrefix}CanonicalizationMethod>');
    } else {
      res.write(' />');
    }
    res
      ..write(
          '<${currentPrefix}SignatureMethod Algorithm="${algo.algorithmName}" />')
      ..write(_createReference(doc, prefix))
      ..write('</${currentPrefix}SignedInfo>');
    return res.toString();
  }

  /// Create the Signature element
  XmlNode _createSignature(String? prefix) {
    var xmlNsAttr = 'xmlns';

    if (prefix != null) {
      xmlNsAttr += ':$prefix';
      prefix += ':';
    } else {
      prefix = '';
    }

    final signatureValueXml =
        '<${prefix}SignatureValue>$signatureValue</${prefix}SignatureValue>';
    //the canonicalization requires to get a valid xml node.
    //we need to wrap the info in a dummy signature since it contains the default namespace.
    final dummySignatureWrapper =
        '<${prefix}Signature $xmlNsAttr="http://www.w3.org/2000/09/xmldsig#">$signatureValueXml</${prefix}Signature>';
    final doc = parseFromString(dummySignatureWrapper);
    return doc.rootElement.firstChild!.copy();
  }

  KeyInfoProvider? get keyInfoProvider => _keyInfoProvider;
  set keyInfoProvider(KeyInfoProvider? value) {
    _keyInfoProvider = value;
    if (value != null) signingKey = value.getKey(keyInfo);
  }

  String get signatureXml => _signatureXml;

  String get originalXmlWithIds => _originalXmlWithIds;

  String get signedXml => _signedXml;
}

abstract class KeyInfoProvider {
  String getKeyInfo(Uint8List? signingKey, String? prefix);

  Uint8List? getKey(String? keyInfo);

  Map<String, dynamic>? get attrs => null;
}

class FileKeyInfo implements KeyInfoProvider {
  final String file;

  FileKeyInfo(this.file);

  @override
  String getKeyInfo(Uint8List? signingKey, String? prefix) {
    var currentPrefix = prefix ?? '';
    currentPrefix =
        currentPrefix.isNotEmpty ? '$currentPrefix:' : currentPrefix;
    final signingCert = StringBuffer();
    if (signingKey != null) {
      final certArray = [signingKey];
      for (var cert in certArray) {
        signingCert.write(
            "<${currentPrefix}X509Certificate>${base64Encode(cert)}</${currentPrefix}X509Certificate>");
      }
    }
    return '<${currentPrefix}X509Data>${signingCert.toString()}</${currentPrefix}X509Data>';
  }

  @override
  Uint8List? getKey(String? keyInfo) => File(file).readAsBytesSync();

  @override
  Map<String, dynamic>? get attrs => null;
}

abstract class CanonicalizationAlgorithm<R> {
  R process(XmlNode node, [Map<String, dynamic> options = const {}]);

  String get algorithmName;
}

abstract class HashAlgorithm {
  String getHash(String xml);

  String get algorithmName;
}

class SHA1 implements HashAlgorithm {
  @override
  String getHash(String xml) =>
      base64Encode(sha1.convert(utf8.encode(xml)).bytes);

  @override
  String get algorithmName => 'http://www.w3.org/2000/09/xmldsig#sha1';
}

class SHA256 implements HashAlgorithm {
  @override
  String getHash(String xml) =>
      base64Encode(sha256.convert(utf8.encode(xml)).bytes);

  @override
  String get algorithmName => 'http://www.w3.org/2001/04/xmlenc#sha256';
}

class SHA512 implements HashAlgorithm {
  @override
  String getHash(String xml) =>
      base64Encode(sha512.convert(utf8.encode(xml)).bytes);

  @override
  String get algorithmName => 'http://www.w3.org/2001/04/xmlenc#sha512';
}

abstract class SignatureAlgorithm {
  String get algorithmName;

  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]);

  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback]);
}

class RSASHA1 implements SignatureAlgorithm {
  @override
  String get algorithmName => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]) {
    final rsa = RSAPrivateKey.fromPEM(utf8.decode(signingKey));
    final res =
        rsa.signSsaPkcs1v15ToBase64(utf8.encode(xml), hasher: EmsaHasher.sha1);
    if (callback != null) callback(null, res);
    return res;
  }

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback]) {
    final parser = RSAPKCSParser();
    final puk = parser.parsePEM(utf8.decode(key)).public;
    if (puk == null) throw ArgumentError('Invalid public key');
    final rsa = RSAPublicKey(puk.modulus, BigInt.from(puk.publicExponent));
    final res =
        rsa.verifySsaPkcs1v15(signatureValue, xml, hasher: EmsaHasher.sha1);
    if (callback != null) callback(null, res);
    return res;
  }
}

class RSASHA256 implements SignatureAlgorithm {
  @override
  String get algorithmName =>
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]) {
    final rsa = RSAPrivateKey.fromPEM(utf8.decode(signingKey));
    final res = rsa.signSsaPkcs1v15ToBase64(utf8.encode(xml),
        hasher: EmsaHasher.sha256);
    if (callback != null) callback(null, res);
    return res;
  }

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback]) {
    final parser = RSAPKCSParser();
    final puk = parser.parsePEM(utf8.decode(key)).public;
    if (puk == null) throw ArgumentError('Invalid public key');
    final rsa = RSAPublicKey(puk.modulus, BigInt.from(puk.publicExponent));
    final res =
        rsa.verifySsaPkcs1v15(signatureValue, xml, hasher: EmsaHasher.sha256);
    if (callback != null) callback(null, res);
    return res;
  }
}

class RSASHA512 implements SignatureAlgorithm {
  @override
  String get algorithmName =>
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]) {
    final rsa = RSAPrivateKey.fromPEM(utf8.decode(signingKey));
    final res = rsa.signSsaPkcs1v15ToBase64(utf8.encode(xml),
        hasher: EmsaHasher.sha512);
    if (callback != null) callback(null, res);
    return res;
  }

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback]) {
    final parser = RSAPKCSParser();
    final puk = parser.parsePEM(utf8.decode(key)).public;
    if (puk == null) throw ArgumentError('Invalid public key');
    final rsa = RSAPublicKey(puk.modulus, BigInt.from(puk.publicExponent));
    final res =
        rsa.verifySsaPkcs1v15(signatureValue, xml, hasher: EmsaHasher.sha512);
    if (callback != null) callback(null, res);
    return res;
  }
}

class HMACSHA1 implements SignatureAlgorithm {
  @override
  String get algorithmName => 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';

  @override
  String getSignature(String xml, Uint8List signingKey,
      [CalculateSignatureCallback? callback]) {
    final hmac = Hmac(sha1, signingKey);
    return base64Encode(hmac.convert(utf8.encode(xml)).bytes);
  }

  @override
  bool verifySignature(String xml, Uint8List key, String signatureValue,
      [ValidateSignatureCallback? callback]) {
    final hmac = Hmac(sha1, key);
    return base64Encode(hmac.convert(utf8.encode(xml)).bytes) == signatureValue;
  }
}

class _Reference {
  String? xpath;
  final List<String> transforms;
  final String digestAlgorithm;
  String? uri;
  final String digestValue;
  final String? inclusiveNamespacesPrefixList;
  final bool isEmptyUri;
  List<dynamic>? ancestorNamespaces;

  _Reference(this.xpath, this.transforms, this.digestAlgorithm, this.uri,
      this.digestValue, this.inclusiveNamespacesPrefixList, this.isEmptyUri);
}
