# Trustee configuration adapter

This is configuration for the existing Trustee operator, not another Trustee
installation or custom service. The base is the Validated Patterns trustee chart
0.10.2, as integrated at CoCo fork commit
`46739d169293934ba253fc956b537f0012ec84c2` (see the source lock for the exact
recorded revision). The RHOAI additions are Base64 decoding on the selected ESO
resource, exact confidential guest bindings in the resource policy, and inclusion
of those bindings in the normal RVPS policy. The original chart license is kept.

Install this adapter only through the normal CoCo Trustee Application, preserving
its existing site values. Never deploy a second copy of the shared service.
