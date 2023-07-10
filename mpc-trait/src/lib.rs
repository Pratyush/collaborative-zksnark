use ark_std::{rand::Rng, UniformRand};
use std::borrow::Cow;

pub trait MpcWire: Clone {
    type Public;

    fn publicize(&mut self) {}

    fn is_shared(&self) -> bool {
        false
    }

    fn publicize_cow<'b>(&'b self) -> Cow<'b, Self> {
        if self.is_shared() {
            let mut s = self.clone();
            s.publicize();
            Cow::Owned(s)
        } else {
            Cow::Borrowed(self)
        }
    }
}

pub trait PubUniformRand: Sized + MpcWire + ark_std::UniformRand {
    fn pub_rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        <Self as UniformRand>::rand(rng)
    }
}

impl<T> MpcWire for std::marker::PhantomData<T> {
    type Public = std::marker::PhantomData<T>;
}

impl<A: MpcWire, B: MpcWire> MpcWire for (A, B) {
    type Public = (A::Public, B::Public);
    struct_mpc_wire_impl!((A, B); (A, 0), (B, 1));
}
impl<A: MpcWire, B: MpcWire, C: MpcWire> MpcWire for (A, B, C) {
    type Public = (A::Public, B::Public, C::Public);
    struct_mpc_wire_impl!((A, B, C); (A, 0), (B, 1), (C, 2));
}
impl<A: MpcWire, B: MpcWire, C: MpcWire, D: MpcWire> MpcWire for (A, B, C, D) {
    type Public = (A::Public, B::Public, C::Public, D::Public);
    struct_mpc_wire_impl!((A, B, C, D); (A, 0), (B, 1), (C, 2), (D, 3));
}

impl<T: MpcWire> MpcWire for Vec<T> {
    type Public = Vec<T::Public>;

    fn publicize(&mut self) {
        for x in self {
            x.publicize();
        }
    }
    fn is_shared(&self) -> bool {
        for x in self {
            if x.is_shared() {
                return true;
            }
        }
        false
    }
}

impl<T: MpcWire> MpcWire for Option<T> {
    type Public = Option<T::Public>;

    fn publicize(&mut self) {
        for x in self {
            x.publicize();
        }
    }

    fn is_shared(&self) -> bool {
        for x in self {
            if x.is_shared() {
                return true;
            }
        }
        false
    }
}

#[macro_export]
macro_rules! struct_mpc_wire_impl {
    // struct_mpc_wire_impl!(STRUCT; FIELD1, FIELD2, ..., FIELDN);
    //
    // Use inside an impl block with the right bounds
    ($s:ty; $( ($x_ty:ty, $x:tt) ),*) => {
        fn publicize(&mut self) {
            $(
                self.$x.publicize();
            )*
        }
        fn is_shared(&self) -> bool {
            $(
                if self.$x.is_shared() {
                    return true;
                }
            )*
            false
        }
    }
}

#[macro_export]
macro_rules! struct_mpc_wire_simp_impl {
    // struct_mpc_wire_impl!(STRUCT; FIELD1, FIELD2, ..., FIELDN);
    //
    // Use inside an impl block with the right bounds
    ($s:ty; $( $x:tt ),*) => {
        fn publicize(&mut self) {
            $(
                self.$x.publicize();
            )*
        }
        fn is_shared(&self) -> bool {
            $(
                if self.$x.is_shared() {
                    return true;
                }
            )*
            false
        }
    }
}
