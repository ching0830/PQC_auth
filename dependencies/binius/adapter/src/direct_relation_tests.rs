use super::*;
#[test]
fn reciprocal_all_parties_and_infinity_sentinel(){
    for party in 0..2047{assert_eq!(gf11_mul(reciprocal(party),party as u16+1),1);}
    assert_eq!(reciprocal(2047),0);
    for plane in 0..11{assert_eq!((0..2048).filter(|&p|reciprocal(p)>>plane&1!=0).count(),1024);}
}
#[test]
fn exact_integer_weight_rejects_same_parity_130(){
    for total in [128,130]{
        let mut raw=vec![0u8;836];for i in 0..total{raw[i/8]|=1<<(i%8);}
        let b=DirectBuilder::new(true);let input=packed_private(&b,Some(&raw),836);weight(&b,&input);
        let c=b.finish();assert_eq!(c.cs.verify(c.values.as_ref().unwrap()).is_ok(),total==128);
    }
}
#[test]
fn systematic_t_word_transpose_matches_independent_row_bit_reference(){
    let raw:Vec<_>=(0..836).map(|i|((i*37+11)^(i>>3))as u8).collect();
    let tail:Vec<_>=(0..TAIL_BYTES).map(|i|((i*7+13)^(i>>7))as u8).collect();
    let b=DirectBuilder::new(true);let input=packed_private(&b,Some(&raw),836);let output=syndrome(&b,&input,&tail);
    let got:Vec<_>=output.iter().map(|e|b.eval(e).unwrap()).collect();
    let mut expected=vec![0u64;26];
    for row in 0..1664{
        let mut value=(raw[row/8]>>(row%8))&1;
        for col in 0..5024{
            let t=row*5024+col;let e=1664+col;
            value^=((tail[t/8]>>(t%8))&1)&((raw[e/8]>>(e%8))&1);
        }
        expected[row/64]|=(value as u64)<<(row%64);
    }
    assert_eq!(got,expected);let c=b.finish();c.cs.verify(c.values.as_ref().unwrap()).unwrap();
}
