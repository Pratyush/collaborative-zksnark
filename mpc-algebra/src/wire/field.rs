use derivative::Derivative;
use log::debug;
use rand::Rng;
use zeroize::Zeroize;

use ark_ff::prelude::*;
use ark_ff::{poly_stub, FftField};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use mpc_trait::MpcWire;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::*;

use super::super::share::field::FieldShare;
use super::super::share::BeaverSource;
use crate::Reveal;
use mpc_net::{MpcMultiNet as Net, MpcNet};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

impl_basics_2!(FieldShare, Field, MpcField);

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyFieldTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: FieldShare<T>> BeaverSource<S, S, S> for DummyFieldTripleSource<T, S> {
    #[inline]
    fn triple(&mut self) -> (S, S, S) {
        (
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S, S) {
        (
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
        )
    }
}

impl<T: Field, S: FieldShare<T>> MpcField<T, S> {
    #[inline]
    pub fn inv(self) -> Option<Self> {
        match self {
            Self::Public(x) => x.inverse().map(MpcField::Public),
            Self::Shared(x) => Some(MpcField::Shared(
                x.inv(&mut DummyFieldTripleSource::default()),
            )),
        }
    }
    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<T>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => out_a.push(x),
                Self::Shared(x) => out_b.push(x),
            }
        }
        if out_a.len() > 0 && out_b.len() > 0 {
            panic!("Heterogeous")
        } else if out_a.len() > 0 {
            Ok(out_a)
        } else {
            Err(out_b)
        }
    }
}
impl<'a, T: Field, S: FieldShare<T>> MulAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= y;
                }
                MpcField::Shared(y) => {
                    let mut t = *y;
                    t.scale(x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(y);
                }
                MpcField::Shared(y) => {
                    let t = x.mul(*y, &mut DummyFieldTripleSource::default());
                    *self = MpcField::Shared(t);
                }
            },
        }
    }
}
impl<T: Field, S: FieldShare<T>> One for MpcField<T, S> {
    #[inline]
    fn one() -> Self {
        MpcField::Public(T::one())
    }
}
impl<T: Field, S: FieldShare<T>> Product for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}
impl<'a, T: Field, S: FieldShare<T> + 'a> Product<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |x, y| x.mul(y.clone()))
    }
}

impl<'a, T: Field, S: FieldShare<T>> DivAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x /= y;
                }
                MpcField::Shared(y) => {
                    let mut t = y.inv(&mut DummyFieldTripleSource::default());
                    t.scale(&x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(&y.inverse().unwrap());
                }
                MpcField::Shared(y) => {
                    let src = &mut DummyFieldTripleSource::default();
                    *x = x.div(*y, src);
                }
            },
        }
    }
}

impl_ref_ops!(Mul, MulAssign, mul, mul_assign, Field, FieldShare, MpcField);
impl_ref_ops!(Add, AddAssign, add, add_assign, Field, FieldShare, MpcField);
impl_ref_ops!(Div, DivAssign, div, div_assign, Field, FieldShare, MpcField);
impl_ref_ops!(Sub, SubAssign, sub, sub_assign, Field, FieldShare, MpcField);

impl<T: Field, S: FieldShare<T>> MpcWire for MpcField<T, S> {
    #[inline]
    fn publicize(&mut self) {
        match self {
            MpcField::Shared(s) => {
                *self = MpcField::Public(s.open());
            }
            _ => {}
        }
        debug_assert!({
            let self_val = if let MpcField::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val.clone());
            true
        })
    }
    #[inline]
    fn is_shared(&self) -> bool {
        match self {
            MpcField::Shared(_) => true,
            MpcField::Public(_) => false,
        }
    }
}

impl<T: Field, S: FieldShare<T>> Reveal for MpcField<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result.clone());
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        MpcField::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        Self::Shared(S::king_share(f, rng))
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        S::king_share_batch(f, rng)
            .into_iter()
            .map(Self::Shared)
            .collect()
    }
    fn init_protocol() {
        S::init_protocol()
    }
    fn deinit_protocol() {
        S::deinit_protocol()
    }
}

from_prim!(bool, Field, FieldShare, MpcField);
from_prim!(u8, Field, FieldShare, MpcField);
from_prim!(u16, Field, FieldShare, MpcField);
from_prim!(u32, Field, FieldShare, MpcField);
from_prim!(u64, Field, FieldShare, MpcField);
from_prim!(u128, Field, FieldShare, MpcField);

impl<T: PrimeField, S: FieldShare<T>> std::str::FromStr for MpcField<T, S> {
    type Err = T::Err;
    #[inline]
    fn from_str(s: &str) -> Result<Self, T::Err> {
        T::from_str(s).map(Self::Public)
    }
}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;
    #[inline]
    fn extension_degree() -> u64 {
        unimplemented!("extension_degree")
    }
    #[inline]
    fn from_base_prime_field_elems(_b: &[<Self as ark_ff::Field>::BasePrimeField]) -> Option<Self> {
        unimplemented!()
        // assert!(b.len() > 0);
        // let shared = b[0].is_shared();
        // assert!(b.iter().all(|e| e.is_shared() == shared));
        // let base_values = b.iter().map(|e| e.unwrap_as_public()).collect::<Vec<_>>();
        // F::from_base_prime_field_elems(&base_values).map(|val| Self::new(val, shared))
    }
    #[inline]
    fn double(&self) -> Self {
        Self::Public(F::from(2u8)) * self
    }
    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self *= Self::Public(F::from(2u8));
        self
    }
    #[inline]
    fn from_random_bytes_with_flags<Fl: Flags>(b: &[u8]) -> Option<(Self, Fl)> {
        F::from_random_bytes_with_flags(b).map(|(val, f)| (Self::Shared(S::from_public(val)), f))
    }
    #[inline]
    fn square(&self) -> Self {
        self.clone() * self
    }
    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        *self *= self.clone();
        self
    }
    #[inline]
    fn inverse(&self) -> Option<Self> {
        self.inv()
    }
    #[inline]
    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.inv().map(|i| {
            *self = i;
            self
        })
    }
    #[inline]
    fn frobenius_map(&mut self, _: usize) {
        unimplemented!("frobenius_map")
    }

    fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_mul(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }
    fn batch_division_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_div(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }
    fn partial_products_in_place(selfs: &mut [Self]) {
        let selfs_shared = selfs[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        if selfs_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            for (self_, new) in selfs.iter_mut().zip(
                S::partial_products(sshares, &mut DummyFieldTripleSource::default()).into_iter(),
            ) {
                *self_ = Self::Shared(new);
            }
        } else {
            for i in 1..selfs.len() {
                let last = selfs[i - 1];
                selfs[i] *= &last;
            }
        }
    }
    fn has_univariate_div_qr() -> bool {
        true
    }
    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<Self>,
    ) -> Option<(
        poly_stub::DensePolynomial<Self>,
        poly_stub::DensePolynomial<Self>,
    )> {
        use poly_stub::DenseOrSparsePolynomial::*;
        let shared_num = match num {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Shared(s) => s,
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Shared(s) => (i, s),
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
        };
        let pub_denom = match den {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Public(s) => s,
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Public(s) => (i, s),
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
        };
        S::univariate_div_qr(shared_num, pub_denom).map(|(q, r)| {
            (
                poly_stub::DensePolynomial {
                    coeffs: q.into_iter().map(|qc| MpcField::Shared(qc)).collect(),
                },
                poly_stub::DensePolynomial {
                    coeffs: r.into_iter().map(|rc| MpcField::Shared(rc)).collect(),
                },
            )
        })
    }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    /// The generator of the multiplicative group of the field
    const GENERATOR: Self = Self::Public(F::GENERATOR);

    /// Let `N` be the size of the multiplicative group defined by the field.
    /// Then `TWO_ADICITY` is the two-adicity of `N`, i.e. the integer `s`
    /// such that `N = 2^s * t` for some odd integer `t`.
    const TWO_ADICITY: u32 = F::TWO_ADICITY;

    /// 2^s root of unity computed by GENERATOR^t
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::Public(F::TWO_ADIC_ROOT_OF_UNITY);

    /// An integer `b` such that there exists a multiplicative subgroup
    /// of size `b^k` for some integer `k`.
    const SMALL_SUBGROUP_BASE: Option<u32> = F::SMALL_SUBGROUP_BASE;

    /// The integer `k` such that there exists a multiplicative subgroup
    /// of size `Self::SMALL_SUBGROUP_BASE^k`.
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = F::SMALL_SUBGROUP_BASE_ADICITY;

    /// GENERATOR^((MODULUS-1) / (2^s *
    /// SMALL_SUBGROUP_BASE^SMALL_SUBGROUP_BASE_ADICITY)) Used for mixed-radix
    /// FFT.
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self> = F::LARGE_SUBGROUP_ROOT_OF_UNITY;
}

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type BigInt = F::BigInt;

    #[inline]
    fn from_bigint(repr: Self::BigInt) -> Option<Self> {
        unimplemented!("No BigInt conversions for shared fields! (from_bigint)")
        // F::from_bigint(repr).map(Self::Shared)
    }
    // We're assuming that into_repr is linear
    #[inline]
    fn into_bigint(&self) -> Self::BigInt {
        unimplemented!("No BigInt reprs for shared fields! (into_repr)")
        //self.unwrap_as_public().into_repr()
    }
}

mod poly_impl {

    use crate::share::*;
    use crate::wire::*;
    use crate::Reveal;
    use ark_ff::PrimeField;
    use ark_poly::domain::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::univariate::DensePolynomial;

    impl<E: PrimeField, S: FieldShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
        type Base = DensePolynomial<E>;
        struct_reveal_simp_impl!(DensePolynomial; coeffs);
    }

    impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>> {
        type Base = Evaluations<F>;

        fn reveal(self) -> Self::Base {
            Evaluations::from_vec_and_domain(
                self.evals.reveal(),
                GeneralEvaluationDomain::new(self.domain().size()).unwrap(),
            )
        }

        fn from_add_shared(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_add_shared(b.evals),
                GeneralEvaluationDomain::new(b.domain().size()).unwrap(),
            )
        }

        fn from_public(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_public(b.evals),
                GeneralEvaluationDomain::new(b.domain().size()).unwrap(),
            )
        }
    }
}
