//! Direct word constraints with one shared private registry.
//!
//! There is no frontend graph, gate evaluator, secret-valued expression cache,
//! or scratch-index encoding. The optional private vector is populated online
//! by the prover; a verifier builds precisely the same CS without that vector.
//! Constant folding depends only on public expression structure, never values
//! of private words. Every materialized intermediate has a ZERO/AND constraint.
use std::{cell::RefCell, collections::BTreeMap};
use binius_core::{constraint_system::{AndConstraint, Composition, ConstraintSystem,
    Operand, StoredOperand, TemplateInterner, Shift, ShiftedValueIndex, ValueIndex, ValueSegment, ValueVec, ZeroConstraint},
    word::Word};
use binius_circuits::keccak::permutation::{R, RC};

/// Sparse affine word. Contains references and public constants, no secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expr { terms: Operand, constant: u64 }
impl Expr {
    pub fn private_index(&self) -> Option<ValueIndex> {
        if self.constant == 0 && self.terms.len() == 1 && self.terms[0].is_unshifted()
            && self.terms[0].value_index.segment() == ValueSegment::Private {
            Some(self.terms[0].value_index)
        } else { None }
    }
    pub fn support(&self) -> usize { self.terms.len() }
}

struct State {
    cs: ConstraintSystem,
    constants: BTreeMap<u64,u32>,
    public: Vec<Word>,
    private: Option<Vec<Word>>,
    count_only: bool,
    column_basis: bool,
    counts: DirectCounts,
    interner: TemplateInterner,
}

/// Exact logical lengths from this lowering, not a memory/RSS measurement.
/// Count-only generation retains the small current expressions/constant table,
/// but no rows, secret words, global wire map, evaluator, or witness vector.
#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub struct DirectCounts {
    pub constants:usize,pub inout:usize,pub private:usize,
    pub and:usize,pub zero:usize,pub operand_terms:usize,
    pub unshifted_terms:usize,pub singly_shifted_terms:usize,pub doubly_shifted_terms:usize,
    pub max_operand_support:usize,
    /// Structs plus actual used operand/constant words; no Vec spare/allocator.
    pub native_len_bytes:usize,
    /// Pinned core v10's canonical serialization length, without serializing.
    pub serialized_bytes:usize,
    pub legacy_native_len_bytes:usize,
    pub unique_templates:usize,pub template_terms:usize,pub template_payload_bytes:usize,pub interner_hash_capacity:usize,
}

pub struct DirectBuilder { state: RefCell<State> }
pub struct DirectCompiled {
    pub cs: ConstraintSystem,
    /// None in verifier/counting mode. Values are not padded here: upstream
    /// packs and pads its segments; ValueVec stores only their real words.
    pub values: Option<ValueVec>,
}

fn canonical(mut terms: Operand, constant: u64) -> Expr {
    terms.sort_unstable();
    let mut output=Vec::with_capacity(terms.len());
    let mut i=0;
    while i<terms.len() {
        let mut j=i+1;
        while j<terms.len() && terms[j]==terms[i] { j+=1; }
        if (j-i)%2==1 { output.push(terms[i]); }
        i=j;
    }
    output.shrink_to_fit();
    Expr { terms:output, constant }
}

impl DirectBuilder {
    pub const MAX_SUPPORT: usize=64;
    pub const MAX_WIDE_INPUT_TERMS:usize=8192;
    pub fn new(prover: bool) -> Self {
        Self { state:RefCell::new(State {
            cs:ConstraintSystem { constants:Vec::new(),n_inout:0,n_private:0,
                zero_constraints:Vec::new(),and_constraints:Vec::new(),
                imul_constraints:Vec::new(),bmul_constraints:Vec::new() },
            constants:BTreeMap::new(),public:Vec::new(),
            private:prover.then(Vec::new),
            count_only:false,column_basis:false,counts:DirectCounts::default(),
            interner:TemplateInterner::new(1_000_000,256<<20),
        }) }
    }
    pub fn new_counting()->Self {
        let out=Self::new(false);out.state.borrow_mut().count_only=true;out
    }
    /// Explicit alternative encoding. Full-relation measurements found this
    /// used MORE CS operand storage without halving the private oracle, so the
    /// smaller D-pinned encoding remains the normal full-relation default.
    pub fn new_column_basis(prover:bool)->Self {
        let out=Self::new(prover);out.state.borrow_mut().column_basis=true;out
    }
    pub fn new_counting_column_basis()->Self {
        let out=Self::new_column_basis(false);out.state.borrow_mut().count_only=true;out
    }
    pub fn is_prover(&self) -> bool { self.state.borrow().private.is_some() }
    pub fn constant(&self, value:u64) -> Expr { Expr { terms:Vec::new(),constant:value } }
    pub fn public_input(&self,value:u64) -> Expr {
        let mut s=self.state.borrow_mut();
        assert!(s.cs.n_inout<ConstraintSystem::MAX_VALUES_PER_SEGMENT,"bounded inout registry");
        let i=s.cs.n_inout; s.cs.n_inout+=1; s.public.push(Word(value));
        Expr { terms:vec![ShiftedValueIndex::plain(ValueIndex::inout(i as u32))],constant:0 }
    }
    fn allocate_private(&self,value:Option<u64>) -> Expr {
        let mut s=self.state.borrow_mut();
        assert!(s.cs.n_private<ConstraintSystem::MAX_VALUES_PER_SEGMENT,"bounded private registry");
        let i=s.cs.n_private; s.cs.n_private+=1;
        if let Some(ref mut private)=s.private {
            private.push(Word(value.expect("prover requires each private word")));
        } else { assert!(value.is_none(),"verifier must not receive private values"); }
        Expr { terms:vec![ShiftedValueIndex::plain(ValueIndex::private(i as u32))],constant:0 }
    }
    pub fn private_input(&self,value:Option<u64>) -> Expr { self.allocate_private(value) }
    /// Online prover evaluation. Not available in verifier mode; never emits
    /// data, creates public constants, or affects constraint shape.
    pub fn eval(&self,expr:&Expr) -> Option<u64> {
        let s=self.state.borrow();
        let private=s.private.as_ref()?;
        let mut value=expr.constant;
        for term in &expr.terms {
            let i=term.value_index.index() as usize;
            let word=match term.value_index.segment() {
                ValueSegment::Constant=>s.cs.constants[i],
                ValueSegment::InOut=>s.public[i],
                ValueSegment::Private=>private[i],
                ValueSegment::Scratch=>unreachable!("direct CS has no scratch"),
            };
            value^=term.outer().apply(term.inner().apply(word)).0;
        }
        Some(value)
    }
    fn operand(&self,expr:&Expr) -> StoredOperand {
        let mut terms=expr.terms.clone();
        if expr.constant!=0 {
            let mut s=self.state.borrow_mut();
            let i=if let Some(&i)=s.constants.get(&expr.constant) {i} else {
                assert!(s.cs.constants.len()<(1usize<<30),"bounded constants");
                let i=s.cs.constants.len() as u32;
                s.cs.constants.push(Word(expr.constant)); s.constants.insert(expr.constant,i); i
            };
            terms.push(ShiftedValueIndex::plain(ValueIndex::constant(i)));
        }
        // Constants precede inout/private in the canonical segment order.
        terms.sort_unstable(); terms.shrink_to_fit();
        let mut s=self.state.borrow_mut();
        match s.interner.intern(terms) {Ok(operand)=>operand,Err(_)=>std::panic::panic_any(s.interner.metrics())}
    }
    fn bounded(&self,expr:Expr) -> Expr {
        if expr.terms.len()>Self::MAX_SUPPORT {self.pin_raw(&expr)} else {expr}
    }
    pub fn xor(&self,a:&Expr,b:&Expr) -> Expr {
        let mut terms=Vec::with_capacity(a.terms.len()+b.terms.len());
        terms.extend_from_slice(&a.terms);terms.extend_from_slice(&b.terms);
        self.bounded(canonical(terms,a.constant^b.constant))
    }
    pub fn xor_many(&self,words:&[Expr]) -> Expr {
        let mut out=self.constant(0);
        for word in words {out=self.xor(&out,word);}
        out
    }
    /// One bounded wide linear reduction followed by a single constrained pin.
    /// This is for public-shape aggregation/syndrome rows, not an unbounded
    /// affine expression or an instruction to expand every circuit operand.
    pub fn xor_many_wide_pin(&self,words:&[Expr])->Expr {
        assert!(words.len()<=Self::MAX_WIDE_INPUT_TERMS,"bounded wide XOR input count");
        let mut count=0usize;let mut constant=0u64;
        for word in words {
            count=count.checked_add(word.terms.len()).expect("bounded wide XOR terms");
            assert!(count<=Self::MAX_WIDE_INPUT_TERMS,"bounded wide XOR terms");
            constant^=word.constant;
        }
        let mut terms=Vec::with_capacity(count);
        for word in words {terms.extend_from_slice(&word.terms);}
        self.pin(&canonical(terms,constant))
    }
    pub fn not(&self,a:&Expr) -> Expr {
        let mut out=a.clone();out.constant^=u64::MAX;out
    }
    pub fn assert_zero(&self,a:&Expr) {
        if a.terms.is_empty() && a.constant==0 {return;}
        let operand=self.operand(a);
        let mut s=self.state.borrow_mut();
        s.counts.zero+=1;Self::count_operand(&mut s.counts,&operand);
        if !s.count_only {s.cs.zero_constraints.push(ZeroConstraint([operand]));}
    }
    pub fn assert_eq(&self,a:&Expr,b:&Expr) {let difference=self.xor(a,b);self.assert_zero(&difference);}
    fn pin_raw(&self,a:&Expr) -> Expr {
        let out=self.allocate_private(self.eval(a));
        let mut terms=a.terms.clone();terms.extend_from_slice(&out.terms);
        self.assert_zero(&canonical(terms,a.constant));out
    }
    pub fn pin(&self,a:&Expr) -> Expr {
        if a.terms.is_empty() || (a.constant==0 && a.terms.len()==1 && a.terms[0].is_unshifted()) {
            a.clone()
        } else { self.pin_raw(a) }
    }
    fn shift(&self,a:&Expr,shift:Shift) -> Expr {
        if shift.is_identity() {return a.clone();}
        // A third nontrivial shift gets its own constrained private word.
        if a.terms.iter().any(|t| t.is_doubly_shifted()) {
            return self.shift(&self.pin_raw(a),shift);
        }
        let mut terms=Vec::with_capacity(a.terms.len());
        for term in &a.terms {
            match Shift::compose(term.inner(),shift) {
                Composition::Zero=>{},
                Composition::Single(s)=>terms.push(ShiftedValueIndex::new(term.value_index,[s,Shift::IDENTITY])),
                Composition::Pair=>terms.push(ShiftedValueIndex::new(term.value_index,[term.inner(),shift])),
            }
        }
        self.bounded(canonical(terms,shift.apply(Word(a.constant)).0))
    }
    pub fn shl(&self,a:&Expr,n:u32) -> Expr {assert!(n<64);self.shift(a,Shift::sll(n as usize))}
    pub fn shr(&self,a:&Expr,n:u32) -> Expr {assert!(n<64);self.shift(a,Shift::srl(n as usize))}
    pub fn sar(&self,a:&Expr,n:u32) -> Expr {assert!(n<64);self.shift(a,Shift::sar(n as usize))}
    pub fn rotl(&self,a:&Expr,n:u32) -> Expr {assert!(n<64);self.shift(a,Shift::rotr(((64-n)%64) as usize))}
    /// Constrain result = (a AND b) XOR c, fusing chi's linear addend into
    /// the AND output operand. Its value remains private.
    pub fn fax(&self,a:&Expr,b:&Expr,c:&Expr) -> Expr {
        if a.terms.is_empty() && b.terms.is_empty() {return self.xor(&self.constant(a.constant&b.constant),c);}
        if a.terms.is_empty() && a.constant==0 || b.terms.is_empty() && b.constant==0 {return c.clone();}
        if a.terms.is_empty() && a.constant==u64::MAX {return self.xor(b,c);}
        if b.terms.is_empty() && b.constant==u64::MAX {return self.xor(a,c);}
        let value=self.eval(a).zip(self.eval(b)).zip(self.eval(c)).map(|((a,b),c)|(a&b)^c);
        let out=self.allocate_private(value);
        let result=self.xor(&out,c);
        self.assert_and_eq(a,b,&result);out
    }
    /// Emit the actual equation a AND b = c without allocating an output word.
    /// This permits an invertible private basis change; it does not remove the
    /// nonlinear relation that a conventional AND-output register would carry.
    pub fn assert_and_eq(&self,a:&Expr,b:&Expr,c:&Expr) {
        if a.terms.is_empty() && b.terms.is_empty() {
            self.assert_eq(c,&self.constant(a.constant&b.constant));return;
        }
        if a.terms.is_empty() && a.constant==0 || b.terms.is_empty() && b.constant==0 {
            self.assert_zero(c);return;
        }
        if a.terms.is_empty() && a.constant==u64::MAX {self.assert_eq(b,c);return;}
        if b.terms.is_empty() && b.constant==u64::MAX {self.assert_eq(a,c);return;}
        let operands=[self.operand(a),self.operand(b),self.operand(c)];
        let mut s=self.state.borrow_mut();s.counts.and+=1;
        for operand in &operands {Self::count_operand(&mut s.counts,operand);}
        if !s.count_only {s.cs.and_constraints.push(AndConstraint(operands));}
    }
    pub fn and(&self,a:&Expr,b:&Expr) -> Expr {self.fax(a,b,&self.constant(0))}
    /// Public configuration selects the measured encoding, never private data.
    pub fn keccak(&self,state:&mut [Expr;25]) {
        let column_basis=self.state.borrow().column_basis;
        if column_basis {self.keccak_column_basis(state);} else {self.keccak_d_pinned(state);}
    }
    /// Explicit alternative Keccak-f1600 with an invertible column basis. Each round commits four
    /// chi outputs and their five-word column parity. The fifth output is their
    /// XOR; ALL five chi equations are constrained, including that fifth one.
    /// The next round's theta column sum cancels to the parity word directly,
    /// saving the additional five private theta-D words of the reference path.
    pub fn keccak_column_basis(&self,state:&mut [Expr;25]) {
        for rc in RC {
            let c:[Expr;5]=std::array::from_fn(|x|self.xor_many(&std::array::from_fn::<_,5,_>(|y|state[x+5*y].clone())));
            let d:[Expr;5]=std::array::from_fn(|x|self.xor(&c[(x+4)%5],&self.rotl(&c[(x+1)%5],1)));
            let mut rotated=state.clone();
            for y in 0..5 {for x in 0..5 {
                rotated[y+5*((2*x+3*y)%5)]=self.rotl(&self.xor(&state[x+5*y],&d[x]),R[x+5*y]);
            }}
            for x in 0..5 {
                let a:[Expr;5]=std::array::from_fn(|y|self.not(&rotated[(x+1)%5+5*y]));
                let b:[Expr;5]=std::array::from_fn(|y|rotated[(x+2)%5+5*y].clone());
                let add:[Expr;5]=std::array::from_fn(|y| {
                    if x==0 && y==0 {self.xor(&rotated[0],&self.constant(rc))}
                    else {rotated[x+5*y].clone()}
                });
                let constants:Option<Vec<u64>>=(0..5).map(|y| {
                    if a[y].terms.is_empty() && b[y].terms.is_empty() && add[y].terms.is_empty() {
                        Some((a[y].constant&b[y].constant)^add[y].constant)
                    } else {None}
                }).collect();
                if let Some(constants)=constants {
                    // This branch depends solely on PUBLIC expression shape.
                    // An all-public permutation emits no private witness.
                    for y in 0..5 {state[x+5*y]=self.constant(constants[y]);}
                    continue;
                }
                let parity_value=(0..5).try_fold(0u64,|parity,y| {
                    self.eval(&a[y]).zip(self.eval(&b[y])).zip(self.eval(&add[y]))
                        .map(|((a,b),add)|parity^((a&b)^add))
                });
                let parity=self.allocate_private(parity_value);
                for y in 0..4 {state[x+5*y]=self.fax(&a[y],&b[y],&add[y]);}
                state[x+20]=self.xor_many(&[parity,state[x].clone(),state[x+5].clone(),
                    state[x+10].clone(),state[x+15].clone()]);
                self.assert_and_eq(&a[4],&b[4],&self.xor(&state[x+20],&add[4]));
            }
        }
    }
    /// Default smaller measured CS encoding: explicit privately pinned theta-D
    /// words and conventional chi-output registers, with the same permutation.
    pub fn keccak_d_pinned(&self,state:&mut [Expr;25]) {
        for rc in RC {
            let c:[Expr;5]=std::array::from_fn(|x|self.xor_many(&std::array::from_fn::<_,5,_>(|y|state[x+5*y].clone())));
            let d:[Expr;5]=std::array::from_fn(|x|self.pin(&self.xor(&c[(x+4)%5],&self.rotl(&c[(x+1)%5],1))));
            let mut rotated=state.clone();
            for y in 0..5 {for x in 0..5 {
                rotated[y+5*((2*x+3*y)%5)]=self.rotl(&self.xor(&state[x+5*y],&d[x]),R[x+5*y]);
            }}
            for y in 0..5 {for x in 0..5 {
                let add=if x==0 && y==0 {self.xor(&rotated[0],&self.constant(rc))} else {rotated[x+5*y].clone()};
                state[x+5*y]=self.fax(&self.not(&rotated[(x+1)%5+5*y]),&rotated[(x+2)%5+5*y],&add);
            }}
        }
    }
    pub fn gf64_mul(&self,a:&Expr,b:&Expr) -> Expr {
        let mut power=a.clone();let mut out=self.constant(0);
        for bit in 0..64 {
            let mask=self.sar(&self.shl(b,63-bit),63);
            out=self.xor(&out,&self.and(&power,&mask));
            if bit!=63 {power=self.gf64_xtime(&power);}
        }
        self.pin(&out)
    }
    fn gf64_xtime(&self,a:&Expr) -> Expr {
        self.xor(&self.shl(a,1),&self.and(&self.sar(a,63),&self.constant(0x1b)))
    }
    pub fn gf64_mul_const(&self,a:&Expr,constant:u64) -> Expr {
        let mut power=a.clone();let mut out=self.constant(0);
        for bit in 0..64 {
            if (constant>>bit)&1!=0 {out=self.xor(&out,&power);}
            if bit!=63 && (constant>>(bit+1))!=0 {power=self.gf64_xtime(&power);}
        }
        self.pin(&out)
    }
    pub fn finish(self) -> DirectCompiled {
        let s=self.state.into_inner();
        assert!(!s.count_only,"count-only builder cannot produce a constraint system or proof");
        // Validation checks actual segment and canonical-shift obligations.
        s.cs.validate().expect("direct core CS must be structurally valid");
        let values=s.private.as_ref().map(|private|s.cs.value_vec_from_data(&s.public,private));
        DirectCompiled {cs:s.cs,values}
    }
    fn count_operand(counts:&mut DirectCounts,operand:&StoredOperand) {
        counts.operand_terms+=operand.len();
        counts.max_operand_support=counts.max_operand_support.max(operand.len());
        for term in operand {
            if term.is_unshifted() {counts.unshifted_terms+=1;}
            else if term.is_doubly_shifted() {counts.doubly_shifted_terms+=1;}
            else {counts.singly_shifted_terms+=1;}
        }
    }
    fn finalize_counts(s:&State)->DirectCounts {
        let mut c=s.counts.clone();
        c.constants=s.cs.constants.len();c.inout=s.cs.n_inout;c.private=s.cs.n_private;
        let m=s.interner.metrics();
        assert_eq!(m.operand_count,c.zero+3*c.and);assert_eq!(m.referenced_terms,c.operand_terms);
        c.unique_templates=m.unique_templates;c.template_terms=m.template_terms;
        c.template_payload_bytes=m.payload_bytes;c.interner_hash_capacity=m.hash_capacity;
        c.native_len_bytes=std::mem::size_of::<ConstraintSystem>()
            +std::mem::size_of::<Word>()*c.constants
            +std::mem::size_of::<AndConstraint>()*c.and
            +std::mem::size_of::<ZeroConstraint>()*c.zero
            +m.payload_bytes;
        c.legacy_native_len_bytes=std::mem::size_of::<ConstraintSystem>()+8*c.constants+72*c.and+24*c.zero+8*c.operand_terms;
        c.serialized_bytes=32+8*c.constants+4*(c.zero+3*c.and)+14*c.operand_terms;
        c
    }
    pub fn counts(&self)->DirectCounts {Self::finalize_counts(&self.state.borrow())}
    pub fn finish_counting(self)->DirectCounts {
        let s=self.state.into_inner();
        assert!(s.count_only,"finish_counting requires explicit count-only builder");
        assert!(s.private.is_none() && s.cs.and_constraints.is_empty() && s.cs.zero_constraints.is_empty());
        Self::finalize_counts(&s)
    }
}

#[cfg(test)]
#[path="direct_core_tests.rs"]
mod tests;
