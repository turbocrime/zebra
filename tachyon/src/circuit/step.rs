// ═══════════════════════════════════════════════════════════════════════
// Spend Leaf  (Index 0)
// ═══════════════════════════════════════════════════════════════════════

/// Leaf step that verifies a single **spend** action.
///
/// Given a [`SpendWitness`], the circuit:
///
/// 1. **Authorization** — `rk == ak + [α]G`
/// 2. **Value commitment** — `cv == [v]V + [rcv]R`
/// 3. **Nullifier derivation** — `nf == Poseidon(nk, ψ, flavor)`
/// 4. **Note commitment** — `cmx == NoteCommit(pk, v, ψ, rcm)`
/// 5. **Accumulator membership** — `cmx ∈ acc(anchor)`
/// 6. **D̂** — `H_curve(H_d(rk ‖ cv))`, single-point accumulator
/// 7. **TĜ** — `H_curve(H_tg(nf))`, single-point accumulator
///
/// The tachygram for a spend is the nullifier.
pub struct SpendLeaf<'params, C: ragu_pcd::Cycle> {
    /// Poseidon parameters for in-circuit hashing.
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: ragu_pcd::Cycle<CircuitField = Fp>> Step<C> for SpendLeaf<'_, C> {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = SpendWitness;
    /// Returns the derived nullifier (as `Fp`) for stamp construction.
    type Aux<'source> = Fp;
    type Left = ();
    type Right = ();
    type Output = StampDigest;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
    )>
    where
        Self: 'dr,
    {
        // ── Allocate note fields ────────────────────────────────────

        let v = Element::alloc(dr, witness.map(|w| Fp::from(w.note.value())))?;
        let psi = Element::alloc(dr, witness.map(|w| w.note.psi()))?;
        let pk = Element::alloc(dr, witness.map(|w| w.note.payment_key().inner()))?;
        let rcm = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.note.rcm())))?;

        // ── Allocate key material ───────────────────────────────────

        let ak = Point::alloc(
            dr,
            witness.map(|w| {
                let bytes: [u8; 32] = w.pak.ak().into();
                EpAffine::from_bytes(&bytes).unwrap()
            }),
        )?;
        let nk = Element::alloc(dr, witness.map(|w| w.pak.nk().inner()))?;

        // ── Allocate randomizers ────────────────────────────────────

        let alpha = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.alpha)))?;
        let rcv = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.rcv.0)))?;

        // ── Anchor ──────────────────────────────────────────────────

        let anchor = Element::alloc(dr, witness.map(|w| w.flavor.0))?;

        // ── 1. Authorization ────────────────────────────────────────
        //
        // rk = ak + [α]G

        let gen_g = Point::constant(dr, todo!("SpendAuth basepoint as EpAffine"))?;
        let alpha_g = alpha.group_scale(dr, &gen_g)?;
        let rk = ak.add_incomplete(dr, &alpha_g, None)?;

        // ── 2. Value commitment ─────────────────────────────────────
        //
        // cv = [v]V + [rcv]R

        let gen_v = Point::constant(dr, todo!("VALUE_COMMIT_V.to_affine()"))?;
        let gen_r = Point::constant(dr, todo!("VALUE_COMMIT_R.to_affine()"))?;
        let v_endo = Endoscalar::extract(dr, v)?;
        let v_scaled = v_endo.group_scale(dr, &gen_v)?;
        let rcv_scaled = rcv.group_scale(dr, &gen_r)?;
        let cv = v_scaled.add_incomplete(dr, &rcv_scaled, None)?;

        // ── 3. Nullifier derivation ─────────────────────────────────
        //
        // nf = Poseidon(nk, ψ, anchor)

        let mut nf_sponge = Sponge::new(dr, self.poseidon);
        // TODO: domain separation tag
        nf_sponge.absorb(dr, &nk)?;
        nf_sponge.absorb(dr, &psi)?;
        nf_sponge.absorb(dr, &anchor)?;
        let nf = nf_sponge.squeeze(dr)?;

        // ── 4. Note commitment ──────────────────────────────────────
        //
        // cmx = NoteCommit(pk, v, ψ, rcm)
        //
        // TBD: Poseidon-based (all field arithmetic) or
        //      Sinsemilla (bit-string, Orchard-style).
        // If Poseidon: absorb pk, v, psi, rcm.field_scale()
        // If Pedersen: rcm is Endoscalar for [rcm]R_cm
        let _cmx: Element<'dr, D> = todo!("note commitment scheme");

        // ── 5. Accumulator membership ───────────────────────────────
        //
        // cmx ∈ acc(anchor)
        //
        // TODO: polynomial accumulator membership proof

        // ── 6. Action digest for D̂ ──────────────────────────────────
        //
        // d_hash = Poseidon(rk.x, rk.y, cv.x, cv.y)
        // d_point = H_curve(d_hash)
        //
        // Blocked: Point has private (x, y) coordinates.
        // Options: (a) add public accessors to Point in ragu,
        //          (b) use Write::write_gadget to serialize into Elements.
        let d_hash: Element<'dr, D> = todo!("Poseidon(rk ‖ cv) — needs Point coord access");
        let d_point = hash_to_curve(dr, &d_hash)?;

        // ── 7. Tachygram hash for TĜ ────────────────────────────────
        //
        // tg = nf for spends → tg_point = H_curve(Poseidon(nf))

        let mut tg_sponge = Sponge::new(dr, self.poseidon);
        // TODO: domain separation tag
        tg_sponge.absorb(dr, &nf)?;
        let tg_hash = tg_sponge.squeeze(dr)?;
        let tg_point = hash_to_curve(dr, &tg_hash)?;

        // ── Encode output header ────────────────────────────────────

        let nf_value = nf.value().map(|v| *v);
        let output = Encoded::from_gadget(StampDigestGadget {
            d_hat: d_point,
            tg_hat: tg_point,
            anchor,
        });

        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            nf_value,
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Output Leaf  (Index 1)
// ═══════════════════════════════════════════════════════════════════════

/// Leaf step that verifies a single **output** action.
///
/// Given an [`OutputWitness`], the circuit:
///
/// 1. **Authorization** — `rk == [α]G`  (no real spend key)
/// 2. **Value commitment** — `cv == [-v]V + [rcv]R`
/// 3. **Note commitment** — `cmx == NoteCommit(pk, v, ψ, rcm)` — this
///    IS the tachygram
/// 4. **D̂** — `H_curve(H_d(rk ‖ cv))`, single-point accumulator
/// 5. **TĜ** — `H_curve(H_tg(cmx))`, single-point accumulator
///
/// No accumulator membership check (the cmx is being *added*, not read).
pub struct OutputLeaf<'params, C: ragu_pcd::Cycle> {
    /// Poseidon parameters for in-circuit hashing.
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: ragu_pcd::Cycle<CircuitField = Fp>> Step<C> for OutputLeaf<'_, C> {
    const INDEX: Index = Index::new(1);

    type Witness<'source> = OutputWitness;
    /// Returns the derived note commitment (as `Fp`) for stamp construction.
    type Aux<'source> = Fp;
    type Left = ();
    type Right = ();
    type Output = StampDigest;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
    )>
    where
        Self: 'dr,
    {
        // ── Allocate note fields ────────────────────────────────────

        let v = Element::alloc(dr, witness.map(|w| Fp::from(w.note.value())))?;
        let psi = Element::alloc(dr, witness.map(|w| w.note.psi()))?;
        let pk = Element::alloc(dr, witness.map(|w| w.note.payment_key().inner()))?;
        let rcm = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.note.rcm())))?;

        // ── Allocate randomizers ────────────────────────────────────

        let alpha = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.alpha)))?;
        let rcv = Endoscalar::alloc(dr, witness.map(|w| extract_endoscalar(w.rcv.0)))?;

        // ── Anchor ──────────────────────────────────────────────────

        let anchor = Element::alloc(dr, witness.map(|w| w.flavor.0))?;

        // ── 1. Authorization ────────────────────────────────────────
        //
        // rk = [α]G  (no real spend auth key — α acts as the full key)

        let gen_g = Point::constant(dr, todo!("SpendAuth basepoint as EpAffine"))?;
        let rk = alpha.group_scale(dr, &gen_g)?;

        // ── 2. Value commitment ─────────────────────────────────────
        //
        // cv = [-v]V + [rcv]R

        let gen_v = Point::constant(dr, todo!("VALUE_COMMIT_V.to_affine()"))?;
        let gen_r = Point::constant(dr, todo!("VALUE_COMMIT_R.to_affine()"))?;
        let neg_v = v.negate(dr);
        let neg_v_endo = Endoscalar::extract(dr, neg_v)?;
        let neg_v_scaled = neg_v_endo.group_scale(dr, &gen_v)?;
        let rcv_scaled = rcv.group_scale(dr, &gen_r)?;
        let cv = neg_v_scaled.add_incomplete(dr, &rcv_scaled, None)?;

        // ── 3. Note commitment ──────────────────────────────────────
        //
        // cmx = NoteCommit(pk, v, ψ, rcm)
        // For outputs, cmx IS the tachygram.
        //
        // TBD: same scheme decision as SpendLeaf
        let cmx: Element<'dr, D> = todo!("note commitment scheme");

        // ── 4. Action digest for D̂ ──────────────────────────────────
        //
        // d_hash = Poseidon(rk.x, rk.y, cv.x, cv.y)
        // d_point = H_curve(d_hash)
        //
        // Same coord-access issue as SpendLeaf.
        let d_hash: Element<'dr, D> = todo!("Poseidon(rk ‖ cv) — needs Point coord access");
        let d_point = hash_to_curve(dr, &d_hash)?;

        // ── 5. Tachygram hash for TĜ ────────────────────────────────
        //
        // tg = cmx for outputs → tg_point = H_curve(Poseidon(cmx))

        let mut tg_sponge = Sponge::new(dr, self.poseidon);
        // TODO: domain separation tag
        tg_sponge.absorb(dr, &cmx)?;
        let tg_hash = tg_sponge.squeeze(dr)?;
        let tg_point = hash_to_curve(dr, &tg_hash)?;

        // ── Encode output header ────────────────────────────────────

        let cmx_value = cmx.value().map(|v| *v);
        let output = Encoded::from_gadget(StampDigestGadget {
            d_hat: d_point,
            tg_hat: tg_point,
            anchor,
        });

        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            cmx_value,
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Merge  (Index 2)
// ═══════════════════════════════════════════════════════════════════════

/// Merge step that combines two sub-proofs.
///
/// 1. Enforces `left.anchor == right.anchor`
/// 2. Accumulates `d_hat = left.d_hat + right.d_hat`  (EC point addition)
/// 3. Accumulates `tg_hat = left.tg_hat + right.tg_hat`  (EC point addition)
///
/// Point addition is **commutative**, so the PCD tree shape does not
/// matter.  [`Point::add_incomplete`] requires distinct x-coordinates;
/// this holds for honest accumulators derived from distinct sub-trees.
///
/// No additional private witness data.
pub struct StampMerge<'params, C: ragu_pcd::Cycle> {
    /// Poseidon parameters (unused in merge, kept for uniformity).
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: ragu_pcd::Cycle<CircuitField = Fp>> Step<C> for StampMerge<'_, C> {
    const INDEX: Index = Index::new(2);

    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = StampDigest;
    type Right = StampDigest;
    type Output = StampDigest;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, ()>,
        left: DriverValue<D, StampDigestData>,
        right: DriverValue<D, StampDigestData>,
    ) -> Result<(
        (
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
        ),
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        // ── Encode input headers ───────────────────────────────────
        //
        // Encoded::new calls Header::encode, which allocates Points
        // and the anchor Element.  as_gadget() gives a reference to
        // the StampDigestGadget.

        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;

        let left_g = left.as_gadget();
        let right_g = right.as_gadget();

        // ── 1. Anchor consistency ──────────────────────────────────

        let anchor_diff = left_g.anchor.sub(dr, &right_g.anchor);
        dr.enforce_zero(|lc| lc.add(anchor_diff.wire()))?;

        // ── 2. Accumulate D̂ ────────────────────────────────────────
        //
        // Pedersen multiset hash merge: point addition on Pallas.
        //
        // add_incomplete requires distinct x-coordinates; honest
        // sub-trees satisfy this.

        let merged_d = left_g.d_hat.add_incomplete(dr, &right_g.d_hat, None)?;

        // ── 3. Accumulate TĜ ───────────────────────────────────────

        let merged_tg = left_g.tg_hat.add_incomplete(dr, &right_g.tg_hat, None)?;

        // ── Encode output ──────────────────────────────────────────

        let output = Encoded::from_gadget(StampDigestGadget {
            d_hat: merged_d,
            tg_hat: merged_tg,
            anchor: left_g.anchor.clone(),
        });

        Ok(((left, right, output), Default::default()))
    }
}
