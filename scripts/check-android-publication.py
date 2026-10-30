#!/usr/bin/env python3
"""Check that published Android runtime dependencies retain their AAR types."""
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository', type=Path, default=Path.home() / '.m2/repository')
parser.add_argument('--version', required=True)
args = parser.parse_args()
ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
for module in ['java', 'kotlin']:
    directory = args.repository / 'com/github/JunWeiUp/common-relay' / module / args.version
    pom = directory / f'{module}-{args.version}.pom'
    text = pom.read_text()
    assert 'published-with-gradle-metadata' not in text, 'POM redirects to lossy module metadata'
    assert not list(directory.glob('*.module')), 'Unexpected Gradle module metadata'
    root = ET.fromstring(text)
    assert root.findtext('m:packaging', namespaces=ns) == 'aar'
    dependencies = {d.findtext('m:artifactId', namespaces=ns): d for d in root.findall('m:dependencies/m:dependency', ns)}
    required = ['jna', 'lazysodium-android'] if module == 'java' else ['java']
    for name in required:
        kind = dependencies[name].findtext('m:type', namespaces=ns)
        if module == 'kotlin' and kind is None:
            # Android project dependencies may omit type; their own POM declares AAR packaging.
            java_pom = args.repository / 'com/github/JunWeiUp/common-relay/java' / args.version / f'java-{args.version}.pom'
            assert ET.parse(java_pom).getroot().findtext('m:packaging', namespaces=ns) == 'aar'
        else:
            assert kind == 'aar', f'{module}: {name} must resolve to AAR'
    assert (directory / f'{module}-{args.version}.aar').is_file()
print('Android Maven publications retain AAR runtime types without module redirection.')
