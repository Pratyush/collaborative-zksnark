use ark_ec::{AffineRepr, CurveGroup, Group};
use derivative::Derivative;
use std::marker::PhantomData;

/// Multi-scalar multiplications
pub trait Msm<G, S>: Send + Sync + 'static {
    fn msm(bases: &[G], scalars: &[S]) -> G;
    fn pre_reveal_check() {}
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct NaiveMsm<G: Group>(pub PhantomData<G>);

impl<G: Group> Msm<G, G::ScalarField> for NaiveMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        bases
            .iter()
            .zip(scalars.iter())
            .map(|(b, s)| {
                let mut b = b.clone();
                b *= *s;
                b
            })
            .fold(G::zero(), |a, b| a + b)
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct AffineMsm<G: CurveGroup>(pub PhantomData<G>);

impl<G: CurveGroup> Msm<G, G::ScalarField> for AffineMsm<G> {
    fn msm(bases: &[G::Affine], scalars: &[G::ScalarField]) -> G {
        G::multi_scalar_mul(bases, scalars).into()
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct ProjectiveMsm<G: CurveGroup>(pub PhantomData<G>);

impl<G: CurveGroup> Msm<G, G::ScalarField> for ProjectiveMsm<G> {
    fn msm(bases: &[G::Affine], scalars: &[G::ScalarField]) -> G {
        let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
        G::multi_scalar_mul(&bases, scalars)
    }
}
