"""Isolated regressions for protocol evidence and offline frame reconstruction."""
import importlib.util
import json
import hashlib
import re
import shutil
import socket
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from contextlib import redirect_stdout
import io

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'Tool' / 'skill' / 'protocol-plugin' / 'scripts'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


repro = module('protocol_repro', SCRIPTS / 'proto-repro.py')
pcap = module('protocol_pcap', SCRIPTS / 'pcap-summary.py')
REFS = SCRIPTS.parent / 'references'


def doc_block(filename, heading, language):
    text = (REFS / filename).read_text(encoding='utf-8')
    section = text.split(heading, 1)[1].split('\n## ', 1)[0]
    return re.search(r'```' + language + r'\n(.*?)\n```', section, re.S).group(1)


def child_run(argv, **kwargs):
    """Decode child output deterministically instead of using the Windows GBK locale."""
    kwargs.update(text=True, encoding='utf-8', errors='replace')
    return subprocess.run(argv, **kwargs)


class ProtocolChain(unittest.TestCase):
    @staticmethod
    def tcp_row(n, src, sport, dst, dport, seq, payload=b'', syn=0, ack=1, fin=0, rst=0, declared=None):
        return '\t'.join(map(str, (n, src, '', sport, dst, '', dport, seq,
            len(payload) if declared is None else declared, syn, ack, fin, rst, payload.hex())))

    def run_pcap(self, rows, direction='forward', extra=()):
        output = '\n'.join(rows) + '\n'
        result = io.StringIO()
        with mock.patch.object(repro, '_which', return_value='tshark'), \
             mock.patch.object(repro, '_tshark_output', return_value=output), redirect_stdout(result):
            rc = repro.main(['--pcap', 'fixture.pcap', '--stream', '7', '--direction', direction, *extra])
        return rc, json.loads(result.getvalue())

    def capture(self, segments, *, client_seq=1000, server_seq=9000, client_fin=True, client_syn=True):
        row = self.tcp_row
        rows = []
        if client_syn:
            rows.append(row(1, '10.0.0.1', 1111, '10.0.0.2', 2222, client_seq, syn=1, ack=0))
        rows.append(row(2, '10.0.0.2', 2222, '10.0.0.1', 1111, server_seq, syn=1))
        for n, (offset, data) in enumerate(segments, 3):
            rows.append(row(n, '10.0.0.1', 1111, '10.0.0.2', 2222, (client_seq + 1 + offset) & 0xffffffff, data))
        if client_fin:
            end = max((offset + len(data) for offset, data in segments), default=0)
            rows.append(row(100, '10.0.0.1', 1111, '10.0.0.2', 2222, (client_seq + 1 + end) & 0xffffffff, fin=1))
        return rows

    def test_pcap_reassembly_out_of_order_retransmit_and_directions(self):
        frame = repro.build_frame(repro.load_schema(None), {'seq': 5}, b'abc')
        rows = self.capture([(10, frame[10:]), (0, frame[:15]), (4, frame[4:12])])
        rows += [self.tcp_row(90, '10.0.0.2', 2222, '10.0.0.1', 1111, 9001, frame),
                 self.tcp_row(101, '10.0.0.2', 2222, '10.0.0.1', 1111, 9001+len(frame), fin=1)]
        for direction in ('forward', 'reverse'):
            with self.subTest(direction=direction):
                rc, result = self.run_pcap(rows, direction)
                self.assertEqual(rc, 0, result)
                self.assertEqual(result['frame_count'], 1)
                self.assertEqual(result['frames'][0]['sha256'], hashlib.sha256(frame).hexdigest())
                self.assertEqual(result['source']['reassembly']['status'], 'complete')

    def test_pcap_reassembly_rejects_gap_conflict_missing_prefix_and_suffix(self):
        frame = repro.build_frame(repro.load_schema(None), {}, b'abc')
        examples = [(self.capture([(0, frame[:4]), (8, frame[8:])]), 'gap'),
                    (self.capture([(5, frame[5:])]), 'gap'),
                    (self.capture([(0, frame), (3, b'Y')]), 'conflicting-overlap'),
                    (self.capture([(0, frame)], client_syn=False), 'missing-or-ambiguous-syn'),
                    (self.capture([(0, frame)], client_fin=False), 'missing-or-ambiguous-fin')]
        for rows, code in examples:
            with self.subTest(code=code, rows=rows):
                rc, result = self.run_pcap(rows)
                self.assertEqual(rc, 2, result)
                self.assertFalse(result['ok'])
                self.assertEqual(result['code'], code)
                self.assertNotIn('frames', result)

    def test_pcap_reassembly_sequence_wrap_and_truncated_packet(self):
        frame = repro.build_frame(repro.load_schema(None), {}, b'abc')
        rows = self.capture([(8, frame[8:]), (0, frame[:8])], client_seq=0xfffffffa)
        rc, result = self.run_pcap(rows)
        self.assertEqual(rc, 0, result)
        self.assertEqual(result['frames'][0]['sha256'], hashlib.sha256(frame).hexdigest())
        rows[2] = self.tcp_row(3, '10.0.0.1', 1111, '10.0.0.2', 2222, 3, b'abc', declared=8)
        rc, result = self.run_pcap(rows)
        self.assertEqual(rc, 2, result)
        self.assertFalse(result['ok'])

    def test_syn_and_fin_payloads_use_tcp_sequence_space(self):
        frame = repro.build_frame(repro.load_schema(None), {}, b'abc')
        rows = [self.tcp_row(1, '10.0.0.1', 1111, '10.0.0.2', 2222, 1000, frame[:6], syn=1, ack=0),
                self.tcp_row(2, '10.0.0.2', 2222, '10.0.0.1', 1111, 9000, syn=1),
                self.tcp_row(3, '10.0.0.1', 1111, '10.0.0.2', 2222, 1007, frame[6:], fin=1)]
        rc, result = self.run_pcap(rows)
        self.assertEqual(rc, 0, result)
        self.assertEqual(result['frames'][0]['sha256'], hashlib.sha256(frame).hexdigest())

    def test_pcap_requires_explicit_flow_and_direction(self):
        for args in (['--pcap', 'fixture.pcap'], ['--pcap', 'fixture.pcap', '--stream', '0'],
                     ['--pcap', 'fixture.pcap', '--direction', 'forward']):
            output = io.StringIO()
            with redirect_stdout(output):
                rc = repro.main(args)
            self.assertEqual(rc, 2)
            self.assertFalse(json.loads(output.getvalue())['ok'])

    def test_real_tshark_on_synthetic_pcap(self):
        if not shutil.which('tshark'):
            self.skipTest('tshark not available on PATH')
        frame = repro.build_frame(repro.load_schema(None), {'seq': 8}, b'abc')
        def packet(reverse, seq, ack, flags, data=b''):
            src, dst = (('10.0.0.2', '10.0.0.1') if reverse else ('10.0.0.1', '10.0.0.2'))
            sport, dport = ((2222, 1111) if reverse else (1111, 2222))
            tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + data
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), 1, 0, 64, 6, 0,
                             socket.inet_aton(src), socket.inet_aton(dst))
            return b'\0'*12 + b'\x08\x00' + ip + tcp
        packets = [packet(False, 1000, 0, 2), packet(True, 9000, 1001, 18),
                   packet(False, 1001, 9001, 16),
                   packet(False, 1011, 9001, 24, frame[10:]),
                   packet(False, 1001, 9001, 24, frame[:15]),
                   packet(False, 1005, 9001, 24, frame[4:12]),
                   packet(True, 9001, 1001+len(frame), 24, frame),
                   packet(False, 1001+len(frame), 9001+len(frame), 17),
                   packet(True, 9001+len(frame), 1002+len(frame), 17)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.pcap'
            with path.open('wb') as fh:
                fh.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                for i, raw in enumerate(packets):
                    fh.write(struct.pack('<IIII', 1700000000+i, 0, len(raw), len(raw)))
                    fh.write(raw)
            for direction in ('forward', 'reverse'):
                proc = child_run([sys.executable, '-B', '-X', 'utf8', str(SCRIPTS / 'proto-repro.py'),
                    '--pcap', str(path), '--stream', '0', '--direction', direction],
                    capture_output=True)
                if proc.returncode:
                    cmd = ['tshark', '-n', '-r', str(path), '-Y', 'tcp.stream==0', '-T', 'fields',
                           '-E', 'separator=/t', '-E', 'occurrence=f']
                    for field in ('frame.number', 'ip.src', 'ipv6.src', 'tcp.srcport', 'ip.dst', 'ipv6.dst',
                                  'tcp.dstport', 'tcp.seq_raw', 'tcp.len', 'tcp.flags.syn', 'tcp.flags.ack',
                                  'tcp.flags.fin', 'tcp.flags.reset', 'tcp.payload'):
                        cmd.extend(('-e', field))
                    debug = child_run(cmd, capture_output=True)
                    self.fail(proc.stdout + proc.stderr + '\n' + repr(debug.stdout) + debug.stderr)
                result = json.loads(proc.stdout)
                self.assertEqual(result['frame_count'], 1)
                self.assertEqual(result['frames'][0]['sha256'], hashlib.sha256(frame).hexdigest())

    def test_pcap_reassembly_limits_and_rst(self):
        frame = repro.build_frame(repro.load_schema(None), {}, b'abc')
        rows = self.capture([(0, frame)])
        with mock.patch.object(repro, 'MAX_REASSEMBLY_BYTES', 8):
            rc, result = self.run_pcap(rows)
        self.assertEqual((rc, result.get('code')), (2, 'byte-limit'))
        rows.append(self.tcp_row(200, '10.0.0.2', 2222, '10.0.0.1', 1111, 9001, rst=1))
        rc, result = self.run_pcap(rows)
        self.assertEqual((rc, result.get('code')), (2, 'reset'))

    def test_pcap_summary_extract_marks_unreassembled(self):
        capture = ROOT / 'Tool' / 'cases' / 'protocol05' / 'target' / 'RADIUS.pcap'
        with tempfile.TemporaryDirectory() as tmp:
            result = pcap.summarize(str(capture), extract=tmp)
            self.assertEqual(result['extract']['tcp_reassembly'], 'not_performed')

    def test_tshark_output_limit_stops_processing(self):
        with mock.patch.object(repro, 'MAX_TSHARK_OUTPUT', 64):
            with self.assertRaises(repro.ReproError) as caught:
                repro._tshark_output([sys.executable, '-B', '-X', 'utf8', '-c', 'print("x" * 1000)'])
        self.assertEqual(caught.exception.code, 'output-limit')

    def test_ambiguous_encapsulated_tcp_fields_are_rejected(self):
        frame = repro.build_frame(repro.load_schema(None), {}, b'abc')
        rows = self.capture([(0, frame)])
        fields = rows[2].split('\t')
        fields[7] += ',42'
        rows[2] = '\t'.join(fields)
        rc, result = self.run_pcap(rows)
        self.assertEqual((rc, result.get('code')), (2, 'invalid-fields'))

    def test_handoff_check_fails_for_failed_claim(self):
        code = doc_block('02-failure-criteria.md', '## 3.7 ', 'bash').split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp) / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'stop.json').write_text('{}', encoding='utf-8')
            (artifacts / 'frames.jsonl').write_text('', encoding='utf-8')
            (artifacts / 'claims.json').write_text('{"claims":[{"id":"bad","rc":2}]}', encoding='utf-8')
            proc = child_run([sys.executable, '-B', '-X', 'utf8', '-c', code],
                             cwd=tmp, capture_output=True)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_stop_ledger_check_rejects_incomplete(self):
        code = doc_block('02-failure-criteria.md', '## 3.1 ', 'bash').split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp) / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'stop.json').write_text('{"stopped":true}', encoding='utf-8')
            proc = child_run([sys.executable, '-B', '-X', 'utf8', '-c', code],
                             cwd=tmp, capture_output=True)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_websocket_example_writes_decodable_frame(self):
        build = doc_block('04-walkthrough-websocket-replay.md', '## 6. 第五步', 'bash').split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        check = doc_block('04-walkthrough-websocket-replay.md', '## 6.1 ', 'python')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'artifacts').mkdir()
            for code in (build, check):
                proc = child_run([sys.executable, '-B', '-X', 'utf8', '-c', code],
                                 cwd=tmp, capture_output=True)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('4242424242424242424', proc.stdout)

    def test_replay_log_hashes_sent_bytes(self):
        code = doc_block('08-replay-and-new-request.md', '## 2.1 ', 'python')
        namespace = {'__name__': 'doc_test'}
        exec(code, namespace)
        class Sink:
            def sendall(self, value): self.sent = value
        link = namespace['Link'].__new__(namespace['Link'])
        link.s, link.log = Sink(), []
        link.send_lock = threading.Lock()
        link.send(b'actual-frame', 'hello')
        self.assertEqual(link.log[0]['len'], len(link.s.sent))
        self.assertEqual(link.log[0]['sha256'], hashlib.sha256(link.s.sent).hexdigest()[:16])

    def test_xor_example_handles_candidate_longer_than_crib(self):
        code = doc_block('07-crypto-and-checksum.md', '## 2.2 ', 'bash').split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp) / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'payload.bin').write_bytes(bytes(range(24)) * 40)
            proc = child_run([sys.executable, '-B', '-X', 'utf8', '-c', code],
                             cwd=tmp, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('候选', proc.stdout)

    def test_crc_example_uses_known_check_value(self):
        section = (REFS / '07-crypto-and-checksum.md').read_text(encoding='utf-8').split('## 4.1 ', 1)[1].split('\n## ', 1)[0]
        blocks = re.findall(r'```bash\n(.*?)\n```', section, re.S)
        code = blocks[-1].split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        proc = child_run([sys.executable, '-B', '-X', 'utf8', '-c', code],
                         capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('0x4b37', proc.stdout)
        self.assertIn('known_vector_ok True', proc.stdout)

    def test_unverified_state_model_never_claims_established(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'model.json'
            path.write_text(json.dumps({'edges': [{'from': 'A', 'to': 'B',
                'evidence_frame': 999999}], 'illegal_transition_proof': 'anything'}), encoding='utf-8')
            result = pcap.state_model(str(path))
            self.assertFalse(result['claims_allowed'])
            self.assertNotEqual(result['verdict'], 'state_machine_established')
            capture = ROOT / 'Tool' / 'cases' / 'protocol05' / 'target' / 'RADIUS.pcap'
            proc = child_run([sys.executable, '-B', '-X', 'utf8', str(SCRIPTS / 'pcap-summary.py'),
                '--file', str(capture), '--state-model', str(path), '--json'],
                capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertFalse(json.loads(proc.stdout)['claims_allowed'])

    def test_unknown_and_absent_checksums_are_not_valid(self):
        schema = repro.load_schema(None)
        frame = repro.build_frame(schema, {'version': 1}, b'abc')
        schema['tail'][0]['algo'] = 'unknown'
        parsed, _ = repro.parse_frames(frame, schema)
        self.assertIsNone(parsed[0]['crc_ok'])
        schema['tail'] = []
        frame = repro.build_frame(schema, {'version': 1}, b'abc')
        parsed, _ = repro.parse_frames(frame, schema)
        self.assertIsNone(parsed[0]['crc_ok'])

    def test_raw_payload_rebuild_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            schema = repro.load_schema(None)
            schema['payload']['encoding'] = 'raw'
            raw = b'\x00\xffABC'
            frame = repro.build_frame(schema, {'version': 1}, raw)
            (tmp / 'schema.json').write_text(json.dumps(schema), encoding='utf-8')
            (tmp / 'input.bin').write_bytes(frame)
            proc = child_run([sys.executable, '-B', '-X', 'utf8', str(SCRIPTS / 'proto-repro.py'),
                '--schema', str(tmp / 'schema.json'), '--input', str(tmp / 'input.bin'),
                '--rebuild', '--out', str(tmp / 'out.bin')], capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual((tmp / 'out.bin').read_bytes(), frame)

    def test_parse_failure_does_not_report_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'truncated.bin'
            path.write_bytes(repro.build_frame(repro.load_schema(None), {}, b'abc')[:-1])
            proc = child_run([sys.executable, '-B', '-X', 'utf8', str(SCRIPTS / 'proto-repro.py'),
                '--input', str(path)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertFalse(json.loads(proc.stdout)['ok'])

    def test_checksum_after_other_tail_field_uses_correct_offset(self):
        schema = repro.load_schema(None)
        schema['tail'].insert(0, {'name': 'reserved', 'size': 2})
        frame = repro.build_frame(schema, {}, b'abc')
        parsed, _ = repro.parse_frames(frame, schema)
        self.assertIs(parsed[0]['crc_ok'], True)

    def test_rebuild_rejects_invalid_index_and_unknown_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.bin'
            path.write_bytes(repro.build_frame(repro.load_schema(None), {}, b'abc'))
            for extra in (['--frame-index', '4'], ['--set', 'sqq=4']):
                with self.subTest(extra=extra):
                    proc = child_run([sys.executable, '-B', '-X', 'utf8', str(SCRIPTS / 'proto-repro.py'),
                        '--input', str(path), '--rebuild', *extra], capture_output=True)
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertFalse(json.loads(proc.stdout)['ok'])


if __name__ == '__main__':
    unittest.main()
