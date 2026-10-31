//! Public constants of the unchanged full research relation, not private data.
pub const FINGERPRINT:&[u8]=&[252,103,6,66,159,16,211,188,197,96,13,75,66,124,166,4,161,159,34,195,30,195,91,23,31,64,81,59,26,75,203,37];
pub const RELATION_ID:&[u8]=&[239,207,214,182,184,124,222,171,133,149,179,142,100,21,187,11,31,113,126,244,69,169,250,120,44,229,3,6,236,129,35,144];
pub const BINDING_ID:&[u8]=&[39,25,250,237,166,55,50,178,23,173,206,166,75,176,36,15,169,86,67,38,79,194,65,14,119,84,24,150,219,11,25,109];
pub const CR_HEADER:&[u8]=&[80,81,83,67,65,80,48,49,0,1,0,1,255,50,252,103,6,66,159,16,211,188,197,96,13,75,66,124,166,4,161,159,34,195,30,195,91,23,31,64,81,59,26,75,203,37,0,0,19,160];
pub const LEAF_DOMAIN:&[u8]=&[80,81,83,65,84,45,66,85,79,86,45,67,65,80,45,48,46,49,47,76,69,65,70,45,67,79,77,77,73,84];
pub const TAPE_DOMAIN:&[u8]=&[80,81,83,65,84,45,66,85,79,86,45,67,65,80,45,48,46,49,47,84,65,80,69,45,69,88,80,65,78,68];
pub const H1_DOMAIN:&[u8]=&[80,81,83,65,84,45,66,85,79,86,45,67,65,80,45,48,46,49,47,70,83,45,72,49];
pub const CONSISTENCY_DOMAIN:&[u8]=&[80,81,83,65,84,45,66,85,79,86,45,67,65,80,45,48,46,49,47,67,79,78,83,73,83,84,69,78,67,89,45,77,65,84,82,73,88];
pub const H2_DOMAIN:&[u8]=&[80,81,83,65,84,45,66,85,79,86,45,67,65,80,45,48,46,49,47,70,83,45,72,50,45,80,82,73,77,69];
pub const PK_DOMAIN:&[u8]=&[80,81,83,65,84,47,72,65,83,72,47,118,51,0,4,98,105,110,100];
pub const KDF_DOMAIN:&[u8]=&[80,81,83,65,84,45,86,51,47,84,82,65,67,69,45,75,68,70,47,118,48,46,49];
pub const KMAC_CUSTOMIZATION:&[u8]=&[80,81,83,65,84,45,86,51,47,84,82,65,67,69,45,77,65,67,47,118,48,46,49];
pub const FULL_DOMAIN:&[u8]=&[80,81,83,65,84,45,86,51,47,73,83,83,85,65,78,67,69,45,70,73,78,65,76,45,80,80,84,47,70,85,76,76,45,77,69,83,83,65,71,69,47,118,48,46,49];
pub const FIELDS:&[(&str,usize,usize)]=&[("CR",0,5074),("r",5074,72),("h1",5146,48),("A",5194,1966080),("Xi",1971274,6976),("selected_seeds",1978250,49152),("SN",2027402,16),("pk_H",2027418,1952),("e",2029370,836)];
pub const X_FIELDS:&[(&str,usize,usize)]=&[("ctx",32,32),("SID",64,32),("RID",96,32),("beta",128,72),("configuration_digest",200,32),("configuration_generation",232,8),("relation_profile_digest",240,32),("cap_profile_fingerprint",272,32),("issuer_map_digest",304,32),("trace_public_key_digest",336,32),("issuer_key_id",368,32),("issue_session_request_digest",400,32),("blind_request_core_digest",432,32),("authenticated_holder_session_digest",464,32),("issuance_authorization_digest",496,32),("quota_reservation_id",528,32),("suite_id",560,2),("session_expiry",562,8)];
pub const SCOPE_FIELDS:&[(&str,usize,usize)]=&[("suite_id",580,2),("ctx",582,32),("issuer_key_id",614,32),("issuer_map_digest",646,32),("cap_profile_fingerprint",678,32),("relation_profile_digest",710,32),("configuration_digest",742,32),("configuration_generation",774,8),("trace_public_key_digest",782,32)];
