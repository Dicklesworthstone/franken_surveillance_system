# EV-T-002: C460 binary derivation is decoder-blocked, not sweep-blocked
- **type:** code_artifact
- **source:** ~/fss-exploit/c460_fw.bin.dec (14MB), docs/exploit/tapo.md §C3-C4
- **finding:** /bin/main lives in a kernel-uImage ramdisk packed in the vendor `sstarXZ` container
  (4 blocks, VLQ size table parsed: (758688,1154048),(743472,1172480),(719328,1899520),(764056,1299008),
  data @0x420270). Custom `tapo_lzma2.py` desyncs (rep-sequence bug); liblzma FORMAT_RAW LZMA2 rejects
  all probed block starts (0x420270..+0x100, 2-byte step). The 0x700200 squashfs is a 3.4MB helper
  partition (no busybox/main). UBI layout in GPL config does not appear in this 14MB image.
- **consequence:** C460 gadget derivation FROM FIRMWARE is blocked on the sstarXZ decoder, not on the
  ASLR sweep. The doc's own prescription (§C5) stands: pull /bin/main from a live shell instead
  (tapo_post.py --pull). The sweep remains the bridge until then.
- **verdict on T-002:** blocked-by-decoder; live-shell pull is the only near-term path.
