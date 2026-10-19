FROM registry.redhat.io/rhoai/odh-kserve-storage-initializer-rhel9@sha256:33def048f85820f43495cac53115f902a5b18bb98d516ac6ac1e9a6905647a6d
USER 0
COPY jwe_decryptor.py /prod_venv/lib64/python3.12/site-packages/kserve_storage/confidential/jwe_decryptor.py
RUN python3 -c 'from kserve_storage.confidential.jwe_decryptor import _StreamingB64UrlDecoder; assert _StreamingB64UrlDecoder().feed(b"YWFh") == b"aaa"'
USER 1000
