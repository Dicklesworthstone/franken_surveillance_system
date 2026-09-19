# Canonical arithmetic model fixture

This repository-generated 495-byte fixture contains no downloaded or trained weights.
It accepts F32 luma `[1,1,8,8]`, normalizes U8 input to 0..1 and adds the explicit scalar
parameter 0.25 using the existing `OP-ADD-001` scalar executor. The output `result` has
the same shape. It tests actual graph loading/execution, not detection quality.

Model SHA-256: `ce1fe0cb63c6db88ada7cb34e8d7e405e6c63de658e0b04885f9e6e47a8ca3c7`.
Embedded graph SHA-256: `b961c8443293bfae727bb5ab3558b3ab0589b4adc04fcb3e3ed935472f7ceeaf`.
Operator-table freeze: `ea84259adbccf747c847b53629fe9176dea0f6cc1874bd5379066d32d30211be`.
Graph/model generation is 3. Scalars and wire lengths use the documented big-endian forms.
The content can be reproduced with `RecordedModel::publish` over an image input, scalar
`parameter` input, `Add` node and `result` output as declared above.
