import 'dart:convert';
import 'dart:io';

/// Loads a shared protocol v2 vector file, e.g. `vectors('sealed-vectors.json')`.
Map<String, dynamic> vectors(String name) =>
    jsonDecode(File('../../protocol/v2/$name').readAsStringSync()) as Map<String, dynamic>;
