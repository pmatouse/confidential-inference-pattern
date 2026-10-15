import importlib.util,json,tempfile,unittest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
spec=importlib.util.spec_from_file_location('release_trust',Path(__file__).resolve().parents[1]/'components/inference-release/trust.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TrustTests(unittest.TestCase):
    def test_pinned_ca_is_not_used_as_server_leaf(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);private=root/'private';public=root/'public'
            pins=m.create(private,public,'authority.demo.svc','demo')
            ca=x509.load_pem_x509_certificate((public/'ca.pem').read_bytes())
            leaf=x509.load_pem_x509_certificate((public/'tls.pem').read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(bytes(pins['certificate_der']),ca.public_bytes(serialization.Encoding.DER))
            self.assertEqual(leaf.issuer,ca.subject)
            ca.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,ec.ECDSA(hashes.SHA256()))
            self.assertNotEqual(ca.public_key().public_numbers(),leaf.public_key().public_numbers())
            self.assertEqual(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),['authority.demo.svc'])
            for p in private.iterdir():self.assertEqual(p.stat().st_mode & 0o077,0)
            self.assertFalse(any('PRIVATE KEY' in p.read_text() for p in public.iterdir()))
            with self.assertRaises(FileExistsError):m.create(private,public,'authority.demo.svc','demo')
