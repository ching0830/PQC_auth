//! Packed-byte direct-core sponge. Public encodings and length limits are the
//! same checked SP 800-185 definitions as the separately tested frontend gadget.
//! No message/key byte or intermediate state becomes a public constant.
use crate::direct_core::{DirectBuilder,Expr};
use crate::sponge::{RATE_BYTES,MAX_ABSORB_BYTES,cshake256_prefix,left_encode,right_encode,
    shake256_permutation_count,cshake256_permutation_count,kmac256_permutation_count};
const RATE_WORDS:usize=RATE_BYTES/8;

fn length(a:usize,b:usize)->usize {
    let n=a.checked_add(b).expect("bounded packed input length");
    assert!(n<=MAX_ABSORB_BYTES,"bounded packed input length");n
}
pub fn public_words(b:&DirectBuilder,bytes:&[u8])->Vec<Expr> {
    assert!(bytes.len()<=MAX_ABSORB_BYTES,"bounded public bytes");
    bytes.chunks(8).map(|chunk| {
        let mut word=[0u8;8];word[..chunk.len()].copy_from_slice(chunk);
        b.constant(u64::from_le_bytes(word))
    }).collect()
}

struct Packed<'a> {b:&'a DirectBuilder,words:Vec<Expr>,bytes:usize}
impl<'a> Packed<'a> {
    fn new(b:&'a DirectBuilder)->Self {Self{b,words:Vec::new(),bytes:0}}
    fn append(&mut self,words:&[Expr],bytes:usize) {
        assert_eq!(words.len(),bytes.div_ceil(8),"exact packed word count");
        let new=length(self.bytes,bytes);
        if bytes%8!=0 {
            let last=&words[words.len()-1];
            let mask=self.b.constant((1u64<<(8*(bytes%8)))-1);
            self.b.assert_eq(last,&self.b.and(last,&mask));
        }
        let offset=self.bytes%8;
        if offset==0 {self.words.extend_from_slice(words);} else {
            let base=self.bytes/8;
            self.words.resize(new.div_ceil(8),self.b.constant(0));
            for (i,word) in words.iter().enumerate() {
                let low=self.b.shl(word,(8*offset) as u32);
                self.words[base+i]=self.b.xor(&self.words[base+i],&low);
                if base+i+1<self.words.len() {
                    let high=self.b.shr(word,(64-8*offset) as u32);
                    self.words[base+i+1]=self.b.xor(&self.words[base+i+1],&high);
                }
            }
        }
        self.bytes=new;
    }
    fn public(&mut self,bytes:&[u8]) {
        length(self.bytes,bytes.len());
        self.append(&public_words(self.b,bytes),bytes.len());
    }
    fn finish(mut self,output_bytes:usize,suffix:u8)->Vec<Expr> {
        assert!(suffix==0x1f || suffix==0x04,"SHAKE/cSHAKE delimiter");
        let padded_words=(self.bytes/RATE_BYTES+1)*RATE_WORDS;
        self.public(&[suffix]);
        self.words.resize(padded_words,self.b.constant(0));
        let last=padded_words-1;
        self.words[last]=self.b.xor(&self.words[last],&self.b.constant(0x80u64<<56));
        let mut state:[Expr;25]=std::array::from_fn(|_|self.b.constant(0));
        for block in self.words.chunks_exact(RATE_WORDS) {
            for (i,word) in block.iter().enumerate() {state[i]=self.b.xor(&state[i],word);}
            self.b.keccak(&mut state);
        }
        let mut output=Vec::with_capacity(output_bytes.div_ceil(8));
        let mut remaining=output_bytes;
        while remaining!=0 {
            let bytes=remaining.min(RATE_BYTES);
            let words=bytes.div_ceil(8);
            for i in 0..words {
                let word=if i+1==words && bytes%8!=0 {
                    self.b.and(&state[i],&self.b.constant((1u64<<(8*(bytes%8)))-1))
                } else {state[i].clone()};
                output.push(word);
            }
            remaining-=bytes;
            if remaining!=0 {self.b.keccak(&mut state);}
        }
        output
    }
}

/// Concatenate canonical packed LE64 fields at arbitrary byte offsets. Each
/// input tail is constrained zero; returned last word also has zero high bytes.
pub fn pack_parts(b:&DirectBuilder,parts:&[(&[Expr],usize)])->Vec<Expr> {
    let mut p=Packed::new(b);
    for &(words,bytes) in parts {p.append(words,bytes);}
    p.words
}
pub fn shake256_fixed(b:&DirectBuilder,message:&[Expr],message_bytes:usize,output_bytes:usize)->Vec<Expr> {
    shake256_permutation_count(message_bytes,output_bytes);
    let mut p=Packed::new(b);p.append(message,message_bytes);p.finish(output_bytes,0x1f)
}
pub fn cshake256_fixed(b:&DirectBuilder,message:&[Expr],message_bytes:usize,output_bytes:usize,
    function_name:&[u8],customization:&[u8])->Vec<Expr> {
    cshake256_permutation_count(message_bytes,output_bytes,function_name,customization);
    let prefix=cshake256_prefix(function_name,customization);
    let suffix=if prefix.is_empty(){0x1f}else{0x04};
    let mut p=Packed::new(b);p.public(&prefix);p.append(message,message_bytes);p.finish(output_bytes,suffix)
}
pub fn kmac256_fixed(b:&DirectBuilder,key:&[Expr],key_bytes:usize,message:&[Expr],message_bytes:usize,
    output_bytes:usize,customization:&[u8])->Vec<Expr> {
    kmac256_permutation_count(key_bytes,message_bytes,output_bytes,customization);
    let mut p=Packed::new(b);p.public(&cshake256_prefix(b"KMAC",customization));
    let mut prefix=left_encode(RATE_BYTES as u64);
    prefix.extend_from_slice(&left_encode((key_bytes as u64)*8));
    let padding=(RATE_BYTES-(prefix.len()+key_bytes)%RATE_BYTES)%RATE_BYTES;
    p.public(&prefix);p.append(key,key_bytes);p.public(&vec![0u8;padding]);
    p.append(message,message_bytes);p.public(&right_encode((output_bytes as u64)*8));
    p.finish(output_bytes,0x04)
}

#[cfg(test)]
#[path="direct_sponge_tests.rs"]
mod tests;
