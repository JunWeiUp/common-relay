import 'dart:io';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:test/test.dart';
void main() {
 test('restart preserves cipher and expiry; cleanup preserves tombstones', () {
  final directory = Directory.systemTemp.createTempSync('relay-journal');
  addTearDown(() => directory.deleteSync(recursive: true));
  var now = 1000000;
  var journal = RelayJournal(directory, clock: () => now);
  final data = Uint8List.fromList([1,2,3]);
  final first = journal.prepare('a','id','b',data,60,(_) => 'cipher');
  now += 30; journal = RelayJournal(directory, clock: () => now);
  final retry = journal.prepare('a','id','b',data,86400,(_) => throw StateError('re-encrypted'));
  expect(retry['body'], first['body']); expect(retry['expires'], first['expires']);
  expect(() => journal.prepare('a','id','b',Uint8List(0),60,(_) => 'bad'), throwsStateError);
  journal.acknowledge('a','b','in');expect(journal.contains('a','b','in'), isTrue);expect(journal.contains('other','b','in'), isFalse);
  now += 30; journal.cleanup();
  expect(() => journal.prepare('a','id','b',data,60,(_) => 'bad'), throwsStateError);
  for(final file in directory.listSync().whereType<File>()) { expect(file.readAsStringSync().contains('cipher'), isFalse); }
  now += 7*86400; journal.cleanup();expect(directory.listSync(), isEmpty);
  journal.prepare('a','done','b',data,60,(_) => 'cipher');journal.complete('a','done');
  expect(journal.prepare('a','done','b',data,60,(_) => 'bad')['status'], 'received');
 });
}
