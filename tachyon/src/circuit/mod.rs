//! Stamp circuit for the Ragu PCD proving system.
//!
//! The stamp circuit verifies all actions in a bundle using a PCD
//! (Proof-Carrying Data) tree:
//!
//! - **[`SpendLeaf`]** (Index 0) — verifies a single spend action
//! - **[`OutputLeaf`]** (Index 1) — verifies a single output action
//! - **[`StampMerge`]** (Index 2) — combines two sub-proofs
//!
//! ## PCD Tree
//!
//! ```text
//!        StampMerge           ← final proof
//!       /          \
//!  SpendLeaf    OutputLeaf    ← one per action
//!  (action₀)    (action₁)
//! ```
//!
//! ## Two Accumulators
//!
//! The proof produces two **Pedersen multiset hash** accumulators as
//! public outputs.  Each is a curve point (on the Pallas curve):
//!
//! - **D̂** — accumulates action digests `H_curve(H(rk_i ‖ cv_i))`
//! - **TĜ** — accumulates hashed tachygrams `H_curve(H(tg_i))`
//!
//! Each element is hashed (Poseidon) then mapped to a curve point
//! (hash-to-curve).  The accumulator is the EC sum of those points:
//!
//! ```text
//! D̂  = Σ H_curve(H_d(rk_i ‖ cv_i))     (Pallas points)
//! TĜ = Σ H_curve(H_tg(tg_i))           (Pallas points)
//! ```
//!
//! Because EC point addition is commutative, the PCD tree shape is
//! irrelevant.  The merge step uses incomplete addition
//! ([`Point::add_incomplete`]).
//!
//! The verifier pre-computes the expected accumulators from public data
//! and checks the final header:
//!
//! ```text
//! expected_d_hat  = Σ H_curve(H_d(rk_i ‖ cv_i))   (from public actions)
//! expected_tg_hat = Σ H_curve(H_tg(tg_i))          (from public tachygrams)
//! ```
//!
//! The **proof** is what binds D̂ to TĜ — without it, there is no way
//! to verify that a particular `rk` corresponds to a particular
//! tachygram.  The recursive SNARK verifier sees only `(D̂, TĜ,
//! anchor)`, never individual `rk`, `cv`, or tachygram values.
//!
//! ## Header: [`StampDigest`]
//!
//! The succinct state carried through the PCD tree.  Five field
//! elements: two curve points (x, y each) plus one scalar.
//!
//! | Field    | Type          | Elements | Description |
//! |----------|---------------|----------|-------------|
//! | `d_hat`  | Pallas point  | 2 (x,y) | Pedersen multiset hash over action digests |
//! | `tg_hat` | Pallas point  | 2 (x,y) | Pedersen multiset hash over tachygrams |
//! | `anchor` | Fp scalar     | 1        | Epoch — must agree across all actions |
//!
//! ## Verification (out-of-circuit)
//!
//! ```text
//! 1. Check each sig_i against rk_i                    (RedPallas)
//! 2. d_hat  = Σ H_curve(H_d(rk_i ‖ cv_i))            (pre-process)
//! 3. tg_hat = Σ H_curve(H_tg(tg_i))                  (pre-process)
//! 4. verify(proof, header=(d_hat, tg_hat, anchor))
//! 5. Check binding sig against Σcv_i                  (RedPallas)
//! ```
//!
//! ## Hash-to-Curve
//!
//! The in-circuit hash-to-curve mapping (field element → Pallas point)
//! is TBD.  Candidates include Sinsemilla (bit-string to curve, used in
//! Orchard) or the simplified SWU map.  The mapping must be:
//! - Efficiently computable in-circuit
//! - Indifferentiable from a random oracle (for multiset hash security)

use group::GroupEncoding;
use pasta_curves::EpAffine;

use ragu_core::Result;
use ragu_core::drivers::{Driver, DriverValue};
use ragu_core::gadgets::{Gadget, GadgetKind, Kind};

use ragu_pcd::header::{Header, Suffix};
use ragu_pcd::step::{Encoded, Index, Step};

use ragu_primitives::io::Write;
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Element, Endoscalar, Point, extract_endoscalar};

use crate::primitives::Fp;
use crate::proof::{OutputWitness, SpendWitness};

mod header;
mod step;

use header::{StampDigest, StampDigestData, StampDigestGadget};
use step::{OutputLeaf, SpendLeaf, StampMerge};

// ═══════════════════════════════════════════════════════════════════════
// Hash-to-curve (stub)
// ═══════════════════════════════════════════════════════════════════════

/// Maps a field element to a Pallas curve point inside the circuit.
///
/// This is the core building block for both accumulators:
/// - D̂ elements: `hash_to_curve(Poseidon(rk ‖ cv))`
/// - TĜ elements: `hash_to_curve(Poseidon(tg))`
///
/// Requirements:
/// - Efficiently computable in-circuit (low constraint count)
/// - Indifferentiable from a random oracle (for multiset hash security)
///
/// Candidates:
/// - **Sinsemilla** — bit-string → Pallas, used in Orchard.
///   Would need `Endoscalar::bits()` or similar decomposition.
/// - **Simplified SWU** — field element → Pallas.
///   More natural for our use case (input is already a field element).
fn hash_to_curve<'dr, D: Driver<'dr, F = Fp>>(
    _dr: &mut D,
    _input: &Element<'dr, D>,
) -> Result<Point<'dr, D, EpAffine>> {
    todo!("hash-to-curve: Sinsemilla or simplified SWU")
}

// ═══════════════════════════════════════════════════════════════════════
// Application builder
// ═══════════════════════════════════════════════════════════════════════

/// Convenience wrapper for building a stamp PCD application.
///
/// Registers the three steps ([`SpendLeaf`], [`OutputLeaf`],
/// [`StampMerge`]) and returns a configured [`ragu_pcd::Application`].
///
/// # Usage
///
/// ```ignore
/// use ragu_pasta::Pasta;
///
/// let params = Pasta::baked();
/// let app = StampApp::build::<Pasta, R>(params)?;
///
/// // Create leaf proofs
/// let (spend_pcd, nf) = app.seed(&mut rng, spend_leaf, spend_witness)?;
/// let (output_pcd, cmx) = app.seed(&mut rng, output_leaf, output_witness)?;
///
/// // Merge into a single stamp proof
/// let stamp_pcd = app.fuse(&mut rng, merge, (), spend_pcd, output_pcd)?;
/// ```
pub struct TachystampApp;

impl TachystampApp {
    /// Header size for the stamp circuit.
    ///
    /// Five field elements: two curve points `(d_hat.x, d_hat.y,
    /// tg_hat.x, tg_hat.y)` and one scalar `(anchor)`.
    pub const HEADER_SIZE: usize = 5;

    /// Builds the stamp PCD application.
    ///
    /// Registers `SpendLeaf` (0), `OutputLeaf` (1), `StampMerge` (2).
    pub fn build<C, R>(
        params: &C::Params,
    ) -> Result<ragu_pcd::Application<'_, C, R, { Self::HEADER_SIZE }>>
    where
        C: ragu_pcd::Cycle<CircuitField = Fp>,
        R: ragu_pcd::Rank,
    {
        let poseidon = C::circuit_poseidon(params);

        let builder = ragu_pcd::ApplicationBuilder::new();
        let builder = builder.register(SpendLeaf::<C> { poseidon })?;
        let builder = builder.register(OutputLeaf::<C> { poseidon })?;
        let builder = builder.register(StampMerge::<C> { poseidon })?;
        builder.finalize(params)
    }
}
