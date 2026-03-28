namespace WabiSabi.Crypto.ZeroKnowledge;

using NBitcoin.Secp256k1;
using NBullet;
using NBullet.Secp256k1;
using Groups;

/// <summary>
/// Bridge between WabiSabi's credential system and NBullet's Bulletproofs++ range proofs.
/// Replaces the sigma-protocol bit-decomposition range proof with a BP++ reciprocal range proof
/// that has O(log n) proof size instead of O(n).
/// </summary>
public class BulletproofPlusPlusRangeProof
{
	/// <summary>
	/// Shared public parameters for BP++ range proofs. Must be the same for prover and verifier.
	/// These are generated once per protocol setup and reused across all credential requests.
	/// </summary>
	public ReciprocalPublic PublicParameters { get; }

	private readonly IGroup _group = Secp256k1Group.Instance;

	/// <summary>
	/// Creates a new instance with deterministic public parameters derived from WabiSabi's generators.
	/// The value generator (G) is set to Generators.Gg and the blinding generator (H[0]) is set to Generators.Gh,
	/// ensuring commitment compatibility: Ma = a*Gg + r*Gh in WabiSabi equals V = v*G + s*H[0] in BP++.
	/// </summary>
	public BulletproofPlusPlusRangeProof()
	{
		// For uint64 range proofs: 16 hex digits (Nd=16), base 16 (Np=16)
		// WNLA needs: lLen = Nd + 1 + 9 = 26 H-points, nLen = Nd = 16 G-points
		// But we also need extension vectors (GVec_, HVec_) for the circuit reduction.
		// Total: 32 H-points, 16 G-points (same as NBullet tests)
		const int Nd = 16;
		const int Np = 16;

		// Generate deterministic generators for the WNLA/circuit system.
		// G is the value generator, H[0] is the blinding generator.
		// Remaining generators are derived deterministically from domain-separated hashes.
		var g = ToPoint(Generators.Gg);
		var hVec = new IPoint[32];
		hVec[0] = ToPoint(Generators.Gh);
		for (int i = 1; i < hVec.Length; i++)
			hVec[i] = ToPoint(Generators.FromText($"BP_H_{i}"));

		var gVec = new IPoint[Nd];
		for (int i = 0; i < gVec.Length; i++)
			gVec[i] = ToPoint(Generators.FromText($"BP_G_{i}"));

		PublicParameters = new ReciprocalPublic
		{
			G = g,
			GVec = gVec[..Nd],
			HVec = hVec[..(Nd + 1 + 9)],
			Nd = Nd,
			Np = Np,
			GVec_ = Array.Empty<IPoint>(), // no extension needed for Nd=16
			HVec_ = hVec[(Nd + 1 + 9)..]
		};
	}

	/// <summary>
	/// Generates a BP++ range proof that the Pedersen commitment Ma = value*Gg + randomness*Gh
	/// commits to a value in [0, 2^64).
	/// </summary>
	/// <param name="amount">The credential amount as a raw ulong.</param>
	/// <param name="randomness">The blinding factor used in the Pedersen commitment.</param>
	public ReciprocalProof Prove(ulong amount, Scalar randomness)
	{
		var x = new Secp256k1Scalar(new Scalar(amount));
		var digits = NumberUtils.UInt64Hex(amount, _group);
		var m = NumberUtils.HexMapping(digits, _group);

		var priv = new ReciprocalPrivate
		{
			X = x,
			M = m,
			Digits = digits,
			S = new Secp256k1Scalar(randomness)
		};

		return Reciprocal.ProveRange(PublicParameters, new Sha256FiatShamirEngine(), priv, _group);
	}

	/// <summary>
	/// Verifies a BP++ range proof against a Pedersen commitment.
	/// </summary>
	/// <param name="ma">The Pedersen commitment Ma = value*Gg + randomness*Gh</param>
	/// <param name="proof">The BP++ range proof to verify</param>
	/// <returns>True if valid, false otherwise.</returns>
	public bool Verify(GroupElement ma, ReciprocalProof proof)
	{
		var commitment = ToPoint(ma);
		var err = Reciprocal.VerifyRange(PublicParameters, commitment, new Sha256FiatShamirEngine(), proof, _group);
		return err == null;
	}

	private static Secp256k1Point ToPoint(GroupElement ge) => new(ge.Ge);
}
