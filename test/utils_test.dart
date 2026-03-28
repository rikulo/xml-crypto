//Copyright (C) 2022 Potix Corporation. All Rights Reserved.
//History: Wed Feb 09 11:30:56 CST 2022
// Author: rudyhuang

import 'dart:convert';
import 'dart:typed_data';

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

  group('normalizeRsaSignatureBase64', () {
    // Modulus that represents a 2048-bit RSA key: expected signature = 256 bytes.
    // BigInt.two.pow(2047) has bitLength == 2048, so expectedLen = (2048+7)~/8 = 256.
    final modulus2048 = BigInt.two.pow(2047);

    test('returns the signature unchanged when it is already the correct length', () {
      final bytes = Uint8List(256);
      for (var i = 0; i < 256; i++) bytes[i] = i & 0xff;
      final b64 = base64Encode(bytes);
      expect(normalizeRsaSignatureBase64(b64, modulus2048), b64);
    });

    test('left-pads a one-byte-short signature with a leading 0x00', () {
      // Build a 256-byte "expected" signature whose first byte is 0x00.
      final expected = Uint8List(256);
      expected[0] = 0x00;
      for (var i = 1; i < 256; i++) expected[i] = i & 0xff;
      final expectedB64 = base64Encode(expected);

      // Simulate the ninja bug: the leading 0x00 is dropped → 255-byte signature.
      final short = expected.sublist(1);
      final shortB64 = base64Encode(short);
      expect(shortB64.length, 340); // 255 bytes → 340 Base64 chars (not 344)

      final normalized = normalizeRsaSignatureBase64(shortB64, modulus2048);
      expect(normalized, expectedB64);
      expect(normalized.length, 344); // 256 bytes → 344 Base64 chars
    });

    test('left-pads a two-byte-short signature with two leading 0x00 bytes', () {
      final expected = Uint8List(256);
      expected[0] = 0x00;
      expected[1] = 0x00;
      for (var i = 2; i < 256; i++) expected[i] = i & 0xff;
      final expectedB64 = base64Encode(expected);

      final short = expected.sublist(2); // 254 bytes
      final shortB64 = base64Encode(short);

      final normalized = normalizeRsaSignatureBase64(shortB64, modulus2048);
      expect(normalized, expectedB64);
    });

    test('throws StateError when the signature is longer than the modulus width', () {
      final bytes = Uint8List(257); // one byte too many for a 2048-bit key
      final b64 = base64Encode(bytes);
      expect(
        () => normalizeRsaSignatureBase64(b64, modulus2048),
        throwsA(isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('257 bytes'),
        )),
      );
    });

    test('works for a 1024-bit key (128-byte expected length)', () {
      final modulus1024 = BigInt.two.pow(1023); // bitLength == 1024

      final expected = Uint8List(128);
      expected[0] = 0x00;
      for (var i = 1; i < 128; i++) expected[i] = i & 0xff;
      final expectedB64 = base64Encode(expected);

      final short = expected.sublist(1); // 127 bytes
      final shortB64 = base64Encode(short);

      final normalized = normalizeRsaSignatureBase64(shortB64, modulus1024);
      expect(normalized, expectedB64);
    });
  });
}