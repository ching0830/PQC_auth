"""LC14 test-only complete20-column tape-to-GF11-LP bridge; no adopted Backend."""
import struct
BASE="6637730a2dd8db74772d0d7bf886125d97f3b47a"
FINGERPRINT=bytes.fromhex("fc6706429f10d3bcc5600d4b427ca604a19f22c31ec35b171f40513b1a4bcb25")
CAP_TAPE_DOMAIN=b"PQSAT-BUOV-CAP-0.1/TAPE-EXPAND"
DESCRIPTOR_DOMAIN=b"PQSAT-LC14/IMPLICIT-ROWS/v0.1"
SOURCE_DOMAIN=b"PQSAT-LC14/PACKED-ROW-SOURCE/v0.1"
PRIVATE_DOMAIN=b"PQSAT-LC14/PRIVATE-IMPLICIT-ROWS/v0.1"
VERSION,CASE,FLAGS=1,14,0
PRIVATE_BYTES=PRIVATE_BODY_BYTES=17152
PRIVATE_BITS,BEGIN=137216,138240
OLD_PRIVATE_BYTES,SUFFIX_OFFSET,SUFFIX_START=11701,11701,94632
LC12_BODY_BYTES,BRIDGE_OFFSET,BRIDGE_COLUMNS=11989,11989,20
BRIDGE_FIRST,BRIDGE_STRIDE,MPLAIN_OFFSET=2047,258,17149
MPLAIN_START=138216
HEADER=struct.Struct(">4sHBBI")
RAW_SLOTS,RAW_ROWS,ALLOC=407336,411697,269096
NNZ_UPPER,GRAPH_BYTES_UPPER,MAX_ARITY=3163552,37615391,2050
PADDED_VARIABLES,PADDED_ROWS=407552,413696
DESCRIPTOR_FIELDS=(
 "public_bits","primary","field_bits","private_bytes","private_bits","begin",
 "coordinates","effective_tape_bits","codec_tape_bits","permutations","rounds",
 "C_per_round","shared_D_per_round","chi_per_round","allocated","raw_slots","raw_rows",
 "raw_nnz_upper","graph_bytes_upper","minimum_padded_variables","minimum_padded_rows",
 "auxzero","empty_rows","padded_nnz_upper","max_arity","repetition","position",
 "prefix0","prefix1","prefix2","suffix_offset","suffix_bytes","resource_admitted","prover_supported",
 "bridge_first","bridge_columns","bridge_offset","bridge_stride","Mplain_offset","Mplain_bits","Mplain_zero_bits")
DESCRIPTOR_VALUES=(256,1023,64,17152,137216,138240,24,2322,2328,5,120,
 320,320,1600,269096,407336,411697,3163552,37615391,407552,413696,
 216,1783,3163984,2050,2,0,5764,7571,9636,11701,288,0,0,
 2047,20,11989,258,17149,18,6)
NUMBERS=struct.Struct(">"+"I"*len(DESCRIPTOR_FIELDS))
DESCRIPTOR_PAYLOAD=(DESCRIPTOR_DOMAIN+b"\0"+SOURCE_DOMAIN+b"\0"+CAP_TAPE_DOMAIN+b"\0"+
 FINGERPRINT+NUMBERS.pack(*DESCRIPTOR_VALUES))
DESCRIPTOR_BYTES=HEADER.size+len(DESCRIPTOR_PAYLOAD)
PRIVATE_PREFIX=PRIVATE_DOMAIN+b"\0"
PRIVATE_FRAME_BYTES=HEADER.size+len(PRIVATE_PREFIX)+32+PRIVATE_BYTES
BACKEND_PROFILE_ID=None
def coordinate_offsets(j):
    if type(j) is not int or not 0<=j<24:raise ValueError("exact old coordinate0..23")
    p=5482 if j==0 else 5765+(j-1)*258 if j<8 else 7572+(j-8)*258 if j<16 else 9637+(j-16)*258
    return p,p+256
def prefix_port(j):
    if type(j) is not int or not 0<=j<24:raise ValueError("exact prefix0..23")
    offset=(5764,7571,9636)[j//8];return offset,j%8,1024+8*offset+j%8
def tape_port(j):
    if type(j) is not int or not 0<=j<2328:raise ValueError("exact tape bit0..2327")
    return prefix_port(j)[2] if j<24 else SUFFIX_START+j-24
def bridge_offsets(b):
    if type(b) is not int or not 0<=b<20:raise ValueError("exact bridge column0..19")
    p=11989+258*b;return p,p+256
def bridge_target(b):
    bridge_offsets(b)
    if b==0:return 43663,6799
    if b==19:return 43664,6800
    return MPLAIN_START+b-1,None
