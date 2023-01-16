//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Tue Feb 15 18:40:31 CST 2022
// Author: rudyhuang

import 'dart:io';

import 'package:xml/xml.dart';
import 'package:xml_crypto/xml_crypto.dart';

void main() {
  final xml = "<library>"
      "<book>"
      "<name>Harry Potter</name>"
      "</book>"
      "</library>";

  //sign an xml document
  signXml(xml, "//*[local-name()='book']", 'client.pem', 'result.xml');

  print('xml signed successfully');

  final signedXml = File('result.xml').readAsStringSync();
  print('validating signature...');

  //validate an xml document
  if (validateXml(signedXml, 'client_public.pem')) {
    print('signature is valid');
  } else {
    print('signature not valid');
  }
}

void signXml(String xml, String xpath, String key, String dest) {
  final sig = SignedXml()
    ..signingKey = File(key).readAsBytesSync()
    ..addReference(xpath)
    ..computeSignature(xml);
  File(dest).writeAsStringSync(sig.signedXml);
}

bool validateXml(String xml, String key) {
  final doc = XmlDocument.parse(xml);
  final signature = doc.findAllElements('Signature').first;
  final sig = SignedXml()
    ..keyInfoProvider = FileKeyInfo(key)
    ..loadSignature(signature);
  final res = sig.checkSignature(xml);
  if (!res) print(sig.validationErrors);
  return res;
}
