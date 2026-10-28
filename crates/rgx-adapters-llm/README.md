# rgx-adapters-llm

Model-file adapters for machine-learning artefacts. They never extract
weights — a multi-gigabyte payload of floats is useless to a text search
— they extract the metadata around them: tensors, shapes, hyperparameters
and architecture strings. That is what an agent grepping a model zoo
actually wants.

## What it claims

| adapter | extensions |
|---|---|
| `gguf` | gguf |
| `safetensors` | safetensors, sft, st |
| `npy` | npy |
| `protobuf` | pb, onnx, model, mlmodel |
| `tiktoken` | tiktoken |
| `keras` | keras |
| `torch` | pt, pt2, pth, ptl, bin |
| `pickle` | pkl, pickle |

All of them declare `Reach::Reveal`: a model file is not text ripgrep can
read.

## How it works

Each adapter checks its own shape before parsing — the `GGUF` magic, the
`\x93NUMPY` header, the tiktoken first line, the plausibility of a
protobuf's opening key — and declines rather than producing a guess. GGUF
is read as a header plus its key/value metadata, where strings are
u64-length prefixed and array values are a u32 type, a u64 length and the
elements. The protobuf arm walks the wire format without a schema, so it
reports what the field structure says rather than what a descriptor file
would have named.

The container formats are handed back for recursion instead of being
parsed here: `keras` is a zip and returns `Outcome::Members`, and `torch`
and `pickle` unpack the same container, so a checkpoint saved as a zip is
walked rather than treated as opaque bytes.

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-llm/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.
