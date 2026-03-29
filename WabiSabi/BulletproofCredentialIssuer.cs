namespace WabiSabi.Crypto;

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NBitcoin.Secp256k1;
using Crypto;
using Groups;
using Randomness;
using ZeroKnowledge;
using ZeroKnowledge.LinearRelation;
using Helpers;
using CredentialRequesting;
using NBullet;

/// <summary>
/// Variant of <see cref="CredentialIssuer"/> that verifies Bulletproofs++ range proofs
/// instead of sigma-protocol bit decomposition range proofs.
/// </summary>
public class BulletproofCredentialIssuer
{
	private long _balance = 0;
	private readonly BulletproofPlusPlusRangeProof _rangeProofSystem;

	public BulletproofCredentialIssuer(
		CredentialIssuerSecretKey credentialIssuerSecretKey,
		BulletproofPlusPlusRangeProof rangeProofSystem,
		WasabiRandom randomNumberGenerator,
		long maxAmount,
		int numberOfCredentials = ProtocolConstants.CredentialNumber)
	{
		if (numberOfCredentials < 1)
			throw new ArgumentOutOfRangeException(nameof(numberOfCredentials), "Must be at least 1.");
		MaxAmount = maxAmount;
		NumberOfCredentials = numberOfCredentials;
		CredentialIssuerSecretKey = Guard.NotNull(nameof(credentialIssuerSecretKey), credentialIssuerSecretKey);
		CredentialIssuerParameters = CredentialIssuerSecretKey.ComputeCredentialIssuerParameters();
		RandomNumberGenerator = Guard.NotNull(nameof(randomNumberGenerator), randomNumberGenerator);
		_rangeProofSystem = rangeProofSystem;
	}

	public long MaxAmount { get; }
	public long Balance => Interlocked.Read(ref _balance);
	public CredentialIssuerSecretKey CredentialIssuerSecretKey { get; }
	public int NumberOfCredentials { get; }

	private HashSet<GroupElement> SerialNumbers { get; } = new();
	private object SerialNumbersLock { get; } = new();
	private WasabiRandom RandomNumberGenerator { get; }
	private CredentialIssuerParameters CredentialIssuerParameters { get; }

	public Task<CredentialsResponse> HandleRequestAsync(ICredentialsRequest registrationRequest, CancellationToken cancel)
		=> Task.Run(() => HandleRequest(registrationRequest), cancel);

	public CredentialsResponse HandleRequest(ICredentialsRequest registrationRequest)
	{
		Guard.NotNull(nameof(registrationRequest), registrationRequest);

		var isNullRequest = registrationRequest.IsNullRequest();
		var requested = registrationRequest.Requested ?? Enumerable.Empty<IssuanceRequest>();
		var presented = registrationRequest.Presented ?? Enumerable.Empty<CredentialPresentation>();

		var requestedCount = requested.Count();
		var requiredNumberOfRequested = registrationRequest.IsPresentationOnlyRequest() ? 0 : NumberOfCredentials;
		if (requestedCount != requiredNumberOfRequested)
			throw new WabiSabiCryptoException(
				WabiSabiCryptoErrorCode.InvalidNumberOfRequestedCredentials,
				$"{NumberOfCredentials} credential requests were expected but {requestedCount} were received.");

		var presentedCount = presented.Count();
		var requiredNumberOfPresentations = isNullRequest ? 0 : NumberOfCredentials;
		if (presentedCount != requiredNumberOfPresentations)
			throw new WabiSabiCryptoException(
				WabiSabiCryptoErrorCode.InvalidNumberOfPresentedCredentials,
				$"{requiredNumberOfPresentations} credential presentations were expected but {presentedCount} were received.");

		// Atomically check and update the balance using compare-and-swap.
		{
			long original, updated;
			do
			{
				original = Interlocked.Read(ref _balance);
				updated = original + registrationRequest.Delta;
				if (updated < 0)
					throw new InvalidOperationException("Negative issuer balance");
			}
			while (Interlocked.CompareExchange(ref _balance, updated, original) != original);
		}

		// Verify BP++ range proofs if this is a bulletproof request
		if (!isNullRequest && registrationRequest is BulletproofRealCredentialsRequest bpRequest)
		{
			if (bpRequest.BulletproofRangeProofs.Length != requestedCount)
				throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.InvalidBitCommitment,
					$"Expected {requestedCount} BP++ range proofs but got {bpRequest.BulletproofRangeProofs.Length}");

			var requestedArray = requested.ToArray();
			for (int i = 0; i < requestedCount; i++)
			{
				if (!_rangeProofSystem.Verify(requestedArray[i].Ma, bpRequest.BulletproofRangeProofs[i]))
					throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.CoordinatorReceivedInvalidProofs,
						$"BP++ range proof {i} failed verification");
			}
		}
		else if (!isNullRequest)
		{
			// For non-bulletproof requests, bit commitments should be empty
			// (BP++ issuer only accepts BP++ requests for non-null requests)
		}

		if (registrationRequest.AreThereDuplicatedSerialNumbers())
			throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.SerialNumberDuplicated);

		var presentedSerialNumbers = presented.Select(x => x.S);

		lock (SerialNumbersLock)
		{
			if (presentedSerialNumbers.Any(s => SerialNumbers.Contains(s)))
				throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.SerialNumberAlreadyUsed, $"Serial number reused");

			foreach (var serialNumber in presentedSerialNumbers)
				SerialNumbers.Add(serialNumber);
		}

		// Build sigma proof statements (show credential + balance only, NO range proofs)
		var statements = new List<Statement>();
		foreach (var presentation in presented)
		{
			var z = presentation.ComputeZ(CredentialIssuerSecretKey);
			statements.Add(ProofSystem.ShowCredentialStatement(presentation, z, CredentialIssuerParameters));
		}

		// For null requests, still verify zero proofs via sigma protocol
		if (isNullRequest)
		{
			foreach (var credentialRequest in requested)
				statements.Add(ProofSystem.ZeroProofStatement(credentialRequest.Ma));
		}

		// Balance proof
		if (!isNullRequest)
		{
			var sumCa = presented.Select(x => x.Ca).Sum();
			var sumMa = requested.Select(x => x.Ma).Sum();
			var absAmountDelta = new Scalar((ulong)Math.Abs(registrationRequest.Delta));
			var deltaA = registrationRequest.Delta < 0 ? absAmountDelta.Negate() : absAmountDelta;
			var balanceTweak = deltaA * Generators.Gg;
			statements.Add(ProofSystem.BalanceProofStatement(balanceTweak + sumCa - sumMa));
		}

		var transcript = BuildTranscript(isNullRequest);

		bool areProofsValid = false;
		try
		{
			areProofsValid = ProofSystem.Verify(transcript, statements, registrationRequest.Proofs);
			if (!areProofsValid)
				throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.CoordinatorReceivedInvalidProofs);
		}
		finally
		{
			if (!areProofsValid)
			{
				lock (SerialNumbersLock)
				{
					foreach (var serialNumber in presentedSerialNumbers)
						SerialNumbers.Remove(serialNumber);
				}
			}
		}

		// Balance was already atomically updated via CAS above.

		var credentials = requested.Select(x => IssueCredential(x.Ma, RandomNumberGenerator.GetScalar())).ToImmutableArray();
		var proofs = ProofSystem.Prove(transcript, credentials.Select(x => x.Knowledge), RandomNumberGenerator);
		var macs = credentials.Select(x => x.Mac);

		return new CredentialsResponse(macs.ToImmutableArray(), proofs.ToImmutableArray());
	}

	private (MAC Mac, Knowledge Knowledge) IssueCredential(GroupElement ma, Scalar t)
	{
		var sk = CredentialIssuerSecretKey;
		var mac = MAC.ComputeMAC(sk, ma, t);
		var knowledge = ProofSystem.IssuerParametersKnowledge(mac, ma, sk);
		return (mac, knowledge);
	}

	private Transcript BuildTranscript(bool isNullRequest)
	{
		var label = $"BulletproofUnifiedRegistration/{NumberOfCredentials}/{isNullRequest}";
		var encodedLabel = Encoding.UTF8.GetBytes(label);
		return new Transcript(encodedLabel);
	}
}
