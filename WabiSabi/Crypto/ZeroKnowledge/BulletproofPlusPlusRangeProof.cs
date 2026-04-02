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
	/// Shared public parameters for BP++ range proofs, computed once and reused.
	/// Generator derivation (48 point constructions) is expensive, so this is cached statically.
	/// </summary>
	public ReciprocalPublic PublicParameters { get; }

	private readonly IGroup _group = Secp256k1Group.Instance;

	// Static cache: generators are deterministic and expensive to derive
	private static readonly Lazy<ReciprocalPublic> CachedPublicParameters = new(() =>
	{
		const int Nd = 16;
		const int Np = 16;

		var g = ToPoint(Generators.Gg);
		var hVec = new IPoint[32];
		hVec[0] = ToPoint(Generators.Gh);
		for (int i = 1; i < hVec.Length; i++)
			hVec[i] = ToPoint(Generators.FromText($"BP_H_{i}"));

		var gVec = new IPoint[Nd];
		for (int i = 0; i < gVec.Length; i++)
			gVec[i] = ToPoint(Generators.FromText($"BP_G_{i}"));

		return new ReciprocalPublic
		{
			G = g,
			GVec = gVec[..Nd],
			HVec = hVec[..(Nd + 1 + 9)],
			Nd = Nd,
			Np = Np,
			GVec_ = Array.Empty<IPoint>(),
			HVec_ = hVec[(Nd + 1 + 9)..]
		};
	});

	public BulletproofPlusPlusRangeProof()
	{
		PublicParameters = CachedPublicParameters.Value;
	}

	/// <summary>
	/// Generates a BP++ range proof that the Pedersen commitment Ma = value*Gg + randomness*Gh
	/// commits to a value in [0, 2^64).
	/// </summary>
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
	public bool Verify(GroupElement ma, ReciprocalProof proof)
	{
		var commitment = ToPoint(ma);
		var err = Reciprocal.VerifyRange(PublicParameters, commitment, new Sha256FiatShamirEngine(), proof, _group);
		return err == null;
	}

	private static Secp256k1Point ToPoint(GroupElement ge) => new(ge.Ge);
}
