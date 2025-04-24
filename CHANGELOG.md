## 3.2.1+1

* The last version that supports Dart 2.x
* minor: canonicalizationAlgorithmForSignedInfo wasn't used
* Added support for custom signature childs (#8 by davidadzgi)

## 3.2.1

* Follow xml-crypto 3.2.1

  This addresses two critical CVE:

    * CVE-2025-29774
    * CVE-2025-29775

## 3.2.0

* Follow xml-crypto 3.2.0
  * Use inclusiveNamespacesPrefixList to generate InclusiveNamespaces
  * Add support for appending attributes to KeyInfo element
  * Updated getKeyInfo function with actual implementation
  * Fix issue in case when namespace has no prefix

## 3.0.1

* Migrate to `xpath_selector` 3.0.1 (#4)
* Handle End-of-Line before parsing Xml (#5)

## 2.1.4

* Correct behavior for XML canonicalization with namespaces and nested elements

## 2.1.3+1

* Fix checkSignature param type
* Do dart format

## 2.1.3

* Initial version
* Ported from `yaronn/xml-crypto@v2.1.3`