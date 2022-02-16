//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 11:30:56 CST 2022
// Author: rudyhuang

import 'package:test/test.dart';
import 'package:xml_crypto/src/utils.dart';

void main() {
  test('test encodeSpecialCharactersInAttribute', () {
    final result = encodeSpecialCharactersInAttribute('<D&D value="done\tdone\r\n">');
    expect(result, '&lt;D&amp;D value=&quot;done&#x9;done&#xD;&#xA;&quot;>');
  });

  test('test encodeSpecialCharactersInText', () {
    final result = encodeSpecialCharactersInText('<D&D value="done\tdone\r\n">');
    expect(result, '&lt;D&amp;D value="done\tdone&#xD;\n"&gt;');
  });
}