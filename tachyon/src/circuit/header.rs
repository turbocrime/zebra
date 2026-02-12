use crate::primitives::Fp;
use ragu_core::Result;
use ragu_core::drivers::Driver;
use ragu_core::gadgets::{Gadget, GadgetKind, Kind};
use ragu_pcd::header::{Header, Suffix};
use ragu_primitives::io::Write;
use ragu_primitives::{Element, Endoscalar, EpAffine, Point};

/// Succinct stamp state carried through the PCD tree.
///
/// Two Pedersen multiset hash accumulators (curve points on Pallas)
/// plus an epoch anchor.  The proof binds D̂ to TĜ — without it there
/// is no public link between an action and its tachygram.
pub struct StampDigest;

/// Raw data for the [`StampDigest`] header.
pub struct StampDigestData {
    /// Action digest accumulator D̂.
    pub d_hat: EpAffine,
    /// Tachygram accumulator TĜ.
    pub tg_hat: EpAffine,
    /// The epoch anchor.
    pub anchor: Fp,
}

/// Gadget representation of [`StampDigestData`].
///
/// Constrains `D::F = Fp` so that `Point<EpAffine>` is well-formed
/// (Pallas base field = Fp).  The [`Write`] derive serialises
/// `(d_hat.x, d_hat.y, tg_hat.x, tg_hat.y, anchor)` — five field
/// elements.
#[derive(Gadget, Write)]
pub struct StampDigestGadget<'dr, #[ragu(driver)] D: Driver<'dr, F = Fp>> {
    /// D̂ accumulator point.
    pub d_hat: Point<'dr, D, EpAffine>,
    /// TĜ accumulator point.
    pub tg_hat: Point<'dr, D, EpAffine>,
    /// Epoch anchor.
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for StampDigest {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data<'source> = StampDigestData;

    /// Five field elements via [`StampDigestGadget`].
    type Output = Kind![Fp; StampDigestGadget<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        Ok(StampDigestGadget {
            d_hat: Point::alloc(dr, witness.map(|d| d.d_hat))?,
            tg_hat: Point::alloc(dr, witness.map(|d| d.tg_hat))?,
            anchor: Element::alloc(dr, witness.map(|d| d.anchor))?,
        })
    }
}
