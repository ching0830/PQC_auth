//! Full research relation on one direct private-word registry.
//! No seed/root image, unselected origins, pi_2, or production adapter.
use anyhow::{ensure,Result};
use crate::{direct_core::{DirectBuilder,Expr},direct_sponge as sponge,direct_relation_profile as p};

pub const PUBLIC_BYTES:usize=846;
pub const PRIVATE_BYTES:usize=2030206;
pub const TAIL_BYTES:usize=1044992;

#[cfg(test)]
#[path="direct_relation_tests.rs"]
mod tests;

fn packed_public(b:&DirectBuilder,raw:&[u8])->Vec<Expr>{
    raw.chunks(8).map(|c|{let mut x=[0u8;8];x[..c.len()].copy_from_slice(c);b.public_input(u64::from_le_bytes(x))}).collect()
}
fn packed_private(b:&DirectBuilder,raw:Option<&[u8]>,bytes:usize)->Vec<Expr>{
    let out:Vec<_>=(0..bytes.div_ceil(8)).map(|i|b.private_input(raw.map(|r|{
        let n=(bytes-8*i).min(8);let mut x=[0u8;8];x[..n].copy_from_slice(&r[8*i..8*i+n]);u64::from_le_bytes(x)
    }))).collect();
    if bytes%8!=0 {b.assert_zero(&b.shr(out.last().unwrap(),(bytes%8*8)as u32));}
    out
}
fn literal(b:&DirectBuilder,raw:&[u8])->Vec<Expr>{
    raw.chunks(8).map(|c|{let mut x=[0u8;8];x[..c.len()].copy_from_slice(c);b.constant(u64::from_le_bytes(x))}).collect()
}
pub fn bit(b:&DirectBuilder,words:&[Expr],i:usize)->Expr{
    b.shr(&b.shl(&words[i/64],(63-i%64)as u32),63)
}
fn pack_bits(b:&DirectBuilder,bits:&[Expr])->Vec<Expr>{
    bits.chunks(64).map(|chunk|b.pin(&b.xor_many(&chunk.iter().enumerate()
        .map(|(i,e)|b.shl(e,i as u32)).collect::<Vec<_>>()))).collect()
}
pub fn bitslice(b:&DirectBuilder,words:&[Expr],start:usize,width:usize)->Vec<Expr>{
    (0..width.div_ceil(64)).map(|i|{
        let at=start+64*i;let j=at/64;let shift=(at%64)as u32;
        let mut value=b.shr(&words[j],shift);
        if shift!=0 && j+1<words.len(){value=b.xor(&value,&b.shl(&words[j+1],64-shift));}
        let remain=width-64*i;
        if remain<64{value=b.and(&value,&b.constant((1u64<<remain)-1));}
        b.pin(&value)
    }).collect()
}
fn byteslice(b:&DirectBuilder,words:&[Expr],start:usize,width:usize)->Vec<Expr>{bitslice(b,words,start*8,width*8)}
fn equal(b:&DirectBuilder,left:&[Expr],right:&[Expr]){
    assert_eq!(left.len(),right.len());for(a,c)in left.iter().zip(right){b.assert_eq(a,c);}
}
fn tuple(b:&DirectBuilder,domain:&[u8],fields:&[(Vec<Expr>,usize)])->Vec<Expr>{
    let mut head=Vec::new();head.extend_from_slice(&(domain.len()as u16).to_be_bytes());head.extend_from_slice(domain);
    head.extend_from_slice(&(fields.len()as u16).to_be_bytes());
    let mut all=vec![(literal(b,&head),head.len())];
    for (words,n)in fields{all.push((literal(b,&(*n as u32).to_be_bytes()),4));all.push((words.clone(),*n));}
    sponge::pack_parts(b,&all.iter().map(|(v,n)|(v.as_slice(),*n)).collect::<Vec<_>>())
}
fn tuple_hash(b:&DirectBuilder,domain:&[u8],fields:&[(Vec<Expr>,usize)],out:usize)->Vec<Expr>{
    let n=2+domain.len()+2+fields.iter().map(|(_,n)|4+n).sum::<usize>();
    sponge::shake256_fixed(b,&tuple(b,domain,fields),n,out)
}
fn gf11_mul(mut a:u16,mut c:u16)->u16{
    let mut v=0;for _ in 0..11{if c&1!=0{v^=a;}c>>=1;a<<=1;if a&2048!=0{a^=0x805;}}v
}
pub fn reciprocal(party:usize)->u16{
    assert!(party<2048);if party==2047{return 0;}let(mut out,mut a,mut e)=(1,party as u16+1,2046);
    while e!=0{if e&1!=0{out=gf11_mul(out,a);}a=gf11_mul(a,a);e>>=1;}out
}
fn weight(b:&DirectBuilder,error:&[Expr]){
    // Balanced exact binary adders: no characteristic-two weight shortcut.
    let mut layer:Vec<Vec<Expr>>=(0..6688).map(|i|vec![bit(b,error,i)]).collect();
    while layer.len()>1{
        let mut next=Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2){
            if pair.len()==1{next.push(pair[0].clone());continue;}
            let mut carry=b.constant(0);let mut sum=Vec::new();
            for i in 0..pair[0].len().max(pair[1].len()){
                let zero=b.constant(0);let a=pair[0].get(i).unwrap_or(&zero);let c=pair[1].get(i).unwrap_or(&zero);
                let parity=b.xor(a,c);sum.push(b.pin(&b.xor(&parity,&carry)));
                carry=b.fax(&carry,&parity,&b.and(a,c));
            }
            sum.push(carry);next.push(sum);
        }
        layer=next;
    }
    for(i,value)in layer[0].iter().enumerate(){b.assert_eq(value,&b.constant((128>>i)&1));}
}
fn syndrome(b:&DirectBuilder,error:&[Expr],tail:&[u8])->Vec<Expr>{
    // Each bit selection is two shifts, hence linear. Keep each public T row
    // as one bounded ZERO relation rather than allocating thousands of ANDs.
    let errors:Vec<_>=(0..6688).map(|i|bit(b,error,i)).collect();
    let output:Vec<_>=(0..1664).map(|row|{
        let mut terms=vec![errors[row].clone()];
        for column in 0..5024{
            let at=row*5024+column;
            if tail[at/8]>>(at%8)&1!=0{terms.push(errors[1664+column].clone());}
        }
        b.xor_many_wide_pin(&terms)
    }).collect();
    pack_bits(b,&output)
}

/// Builds ALL rules, either count-only, symbolic materialization, or UE values.
/// The caller must independently bind raw public T to NCC's expected digest.
/// The same input field registry feeds every component; no supplied M/tapes.
pub fn compile(b:&DirectBuilder,public:&[u8],secret:Option<&[u8]>,tail:&[u8],trace_digest:&[u8;32])->Result<()>{
    ensure!(public.len()==PUBLIC_BYTES && tail.len()==TAIL_BYTES,"fixed public widths");
    ensure!(secret.is_none_or(|s|s.len()==PRIVATE_BYTES),"fixed private width");
    ensure!(b.is_prover()==secret.is_some(),"separate prover/verifier data");
    let public_words=packed_public(b,public);
    if PUBLIC_BYTES%8!=0{b.assert_zero(&b.shr(public_words.last().unwrap(),(PUBLIC_BYTES%8*8)as u32));}
    let fields:Vec<_>=p::FIELDS.iter().map(|(_,start,n)|packed_private(b,secret.map(|s|&s[*start..*start+*n]),*n)).collect();
    let field=|name:&str|->&[Expr]{&fields[p::FIELDS.iter().position(|(n,_,_)|*n==name).unwrap()]};
    let x=|name:&str|->Vec<Expr>{let(_,start,n)=p::X_FIELDS.iter().find(|(n,_,_)|*n==name).unwrap();byteslice(b,&public_words,*start,*n)};
    equal(b,&byteslice(b,&public_words,0,32),&literal(b,p::FINGERPRINT));
    equal(b,&x("cap_profile_fingerprint"),&literal(b,p::FINGERPRINT));
    equal(b,&x("relation_profile_digest"),&literal(b,p::RELATION_ID));
    equal(b,&x("trace_public_key_digest"),&literal(b,trace_digest));
    equal(b,&byteslice(b,&public_words,570,10),&literal(b,b"LCAPSCP1\0\x01"));
    equal(b,&byteslice(b,&public_words,814,32),&literal(b,p::BINDING_ID));
    for(name,start,n)in p::SCOPE_FIELDS{equal(b,&byteslice(b,&public_words,*start,*n),&x(name));}
    // The captured raw T identity is externally trusted, and constrained above.
    equal(b,&byteslice(b,field("CR"),0,50),&literal(b,p::CR_HEADER));
    let salt=byteslice(b,field("CR"),50,48);
    let fp=literal(b,p::FINGERPRINT);
    let mut tapes=Vec::with_capacity(2048);
    for party in 0..2048{
        let params=[(fp.clone(),32),(salt.clone(),48),(literal(b,&2u16.to_be_bytes()),2),
            (literal(b,&(party as u16).to_be_bytes()),2),(byteslice(b,field("selected_seeds"),party*24,24),24)];
        let leaf=tuple_hash(b,p::LEAF_DOMAIN,&params,48);
        equal(b,&leaf,&byteslice(b,field("A"),(8192+party)*48,48));
        tapes.push(tuple_hash(b,p::TAPE_DOMAIN,&params,291));
    }
    let reciprocals:Vec<_>=(0..2048).map(reciprocal).collect();
    let mut planes=Vec::with_capacity(12);
    for plane in 0..12{
        let mut words=Vec::with_capacity(37);
        for j in 0..37{
            let terms:Vec<_>=tapes.iter().enumerate().filter(|(p,_)|plane==0 || reciprocals[*p]>>(plane-1)&1!=0)
                .map(|(_,t)|t[j].clone()).collect();
            let mut value=b.xor_many_wide_pin(&terms);
            if j==36{value=b.and(&value,&b.constant((1<<18)-1));}
            words.push(value);
        }
        planes.push(words);
    }
    drop(tapes);
    let mut corrected=byteslice(b,field("CR"),466,256);
    for(i,value)in corrected.iter_mut().enumerate(){*value=b.pin(&b.xor(value,&planes[0][i]));}
    let mut mhat=byteslice(b,field("CR"),722,32);
    let plain_mhat=bitslice(b,&planes[0],2066,256);
    for(i,value)in mhat.iter_mut().enumerate(){*value=b.pin(&b.xor(value,&plain_mhat[i]));}
    equal(b,&corrected[..9],field("r"));
    let h1=tuple_hash(b,p::H1_DOMAIN,&[(fp.clone(),32),(x("ctx"),32),(salt,48),
        (field("A").to_vec(),1966080),(byteslice(b,field("CR"),178,4896),4896)],48);
    equal(b,&h1,field("h1"));
    let chi=tuple_hash(b,p::CONSISTENCY_DOMAIN,&[(fp.clone(),32),(field("h1").to_vec(),48)],32);
    for plane in 0..12{
        let coeff=if plane==0{corrected.clone()}else{planes[plane][..32].to_vec()};
        for point in 0..4{
            let mut acc=coeff[31].clone();
            for k in (0..31).rev(){acc=b.pin(&b.xor(&b.gf64_mul(&acc,&chi[point]),&coeff[k]));}
            let target=if plane==0{byteslice(b,field("CR"),146+point*8,8)[0].clone()}else{
                let bits:Vec<_>=(0..64).map(|k|bit(b,field("Xi"),864*8+11*(point*64+k)+plane-1)).collect();
                pack_bits(b,&bits)[0].clone()
            };
            let mask=if plane==0{mhat[point].clone()}else{bitslice(b,&planes[plane],2066+64*point,64)[0].clone()};
            b.assert_eq(&b.xor(&acc,&mask),&target);
        }
    }
    let alpha=byteslice(b,field("CR"),146,32);let mut xi_at=0;
    for repetition in 0..18{
        equal(b,&byteslice(b,field("Xi"),xi_at,32),&alpha);
        xi_at+=32+if repetition<2{384}else{352};
    }
    assert_eq!(xi_at,6976);
    let h2=tuple_hash(b,p::H2_DOMAIN,&[(fp,32),(field("h1").to_vec(),48),(field("Xi").to_vec(),6976)],48);
    equal(b,&h2,&byteslice(b,field("CR"),98,48));
    weight(b,field("e"));
    let syndrome=syndrome(b,field("e"),tail);
    let pk_params=[(literal(b,p::PK_DOMAIN),p::PK_DOMAIN.len()),(x("ctx"),32),(literal(b,&1952u64.to_be_bytes()),8),(field("pk_H").to_vec(),1952)];
    let pk_input=sponge::pack_parts(b,&pk_params.iter().map(|(v,n)|(v.as_slice(),*n)).collect::<Vec<_>>());
    let q=sponge::shake256_fixed(b,&pk_input,p::PK_DOMAIN.len()+32+8+1952,48);
    let kdf_parts=[(literal(b,p::KDF_DOMAIN),p::KDF_DOMAIN.len()),(x("ctx"),32),(field("e").to_vec(),836),
        (syndrome.clone(),208),(x("ctx"),32),(field("SN").to_vec(),16),(q.clone(),48)];
    let kdf_input=sponge::pack_parts(b,&kdf_parts.iter().map(|(v,n)|(v.as_slice(),*n)).collect::<Vec<_>>());
    let stream=sponge::shake256_fixed(b,&kdf_input,kdf_parts.iter().map(|(_,n)|*n).sum(),80);
    let rid_sn=sponge::pack_parts(b,&[(&x("RID"),32),(field("SN"),16)]);
    let cmu:Vec<_>=rid_sn.iter().zip(&stream[..6]).map(|(a,c)|b.pin(&b.xor(a,c))).collect();
    let macparts=[(syndrome.clone(),208),(cmu.clone(),48),(x("ctx"),32),(field("SN").to_vec(),16),(q.clone(),48)];
    let macinput=sponge::pack_parts(b,&macparts.iter().map(|(v,n)|(v.as_slice(),*n)).collect::<Vec<_>>());
    let gamma=sponge::kmac256_fixed(b,&stream[6..10],32,&macinput,352,32,p::KMAC_CUSTOMIZATION);
    let mparts=[(x("ctx"),32),(field("SN").to_vec(),16),(q,48),(literal(b,&208u32.to_be_bytes()),4),
        (syndrome,208),(cmu,48),(gamma,32)];
    assert_eq!(mparts.iter().map(|(_,n)|*n).sum::<usize>(),388);
    let mut fullparts=vec![(literal(b,p::FULL_DOMAIN),p::FULL_DOMAIN.len()),(byteslice(b,&public_words,570,276),276),
        (literal(b,&388u64.to_be_bytes()),8)];fullparts.extend(mparts);
    fullparts.extend([(literal(b,&5074u64.to_be_bytes()),8),(field("CR").to_vec(),5074)]);
    let fullinput=sponge::pack_parts(b,&fullparts.iter().map(|(v,n)|(v.as_slice(),*n)).collect::<Vec<_>>());
    let full=sponge::shake256_fixed(b,&fullinput,5799,72);
    let beta=x("beta");for(i,value)in full.iter().enumerate(){b.assert_eq(&b.xor(value,&field("r")[i]),&beta[i]);}
    Ok(())
}
