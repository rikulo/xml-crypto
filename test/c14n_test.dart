//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 14:32:04 CST 2022
// Author: rudyhuang

import 'package:test/test.dart';
import 'package:xml/xml.dart';
import 'package:xml_crypto/xml_crypto.dart';
import 'package:xml_crypto/src/c14n_canonicalization.dart';
import 'package:xpath_selector/xpath_selector.dart';

void testC14nCanonicalization(String xml, String xpath, String expected) {
  final doc = XmlDocument.parse(xml);
  final elem = XPath(XmlNodeTree(doc)).query(xpath).node?.node;
  if (elem == null) {
    throw Exception('$xpath not found in $xml');
  }

  final can = C14nCanonicalization();
  final result = can.process(elem, {
    'ancestorNamespaces': findAncestorNs(doc, xpath),
  });
  expect(result, expected);
}

void testFindAncestorNs(String xml, String xpath, List<XmlNamespace> expected) {
  final doc = XmlDocument.parse(xml);
  final result = findAncestorNs(doc, xpath);
  expect(result, expected);
}

void main() {
  group('findAncestorNs', () {
    test('Correctly picks up root ancestor namespace', () {
      final xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('aaa', 'bbb')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Correctly picks up intermediate ancestor namespace', () {
      final xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('aaa', 'bbb')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces declared in the one same element', () {
      final xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('aaa', 'bbb'), XmlNamespace('ccc', 'ddd')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces scattered among depth', () {
      final xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('ccc', 'ddd'), XmlNamespace('aaa', 'bbb')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces without duplicate', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('ccc', 'bbb')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Correctly eliminates duplicate prefix', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('ccc', 'AAA')];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Exclude namespace which is already declared with same prefix on target node', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const <XmlNamespace>[];

      testFindAncestorNs(xml, xpath, expected);
    });

    test('Ignores namespace declared in the target xpath node', () {
      final xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:ccc='ddd'></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = const [XmlNamespace('aaa', 'bbb')];

      testFindAncestorNs(xml, xpath, expected);
    });
  });

  group('C14n', () {
    test('Correctly picks up root ancestor namespace', () {
      final xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Correctly picks up intermediate ancestor namespace', () {
      final xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces declared in the one same element', () {
      final xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces scattered among depth', () {
      final xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Correctly picks up multiple ancestor namespaces without duplicate', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:ccc="bbb"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Correctly eliminates duplicate prefix', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:ccc="AAA"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Exclude namespace which is already declared with same prefix on target node', () {
      final xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:ccc="AAA"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Preserve namespace declared in the target xpath node', () {
      final xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:ccc='ddd'></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });

    test('Don\'t redeclare an attribute\'s namespace prefix if already in scope', () {
      final xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:aaa='bbb' aaa:foo='bar'></child2></child1></root>";
      final xpath = "/root/child1/child2";
      final expected = '<child2 xmlns:aaa="bbb" aaa:foo="bar"></child2>';

      testC14nCanonicalization(xml, xpath, expected);
    });
  });
}