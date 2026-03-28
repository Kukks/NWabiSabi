namespace WabiSabi.Crypto;

using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using NBitcoin.Secp256k1;
using Crypto;
using Collections;
using Groups;
using Randomness;
using ZeroKnowledge;
using ZeroKnowledge.LinearRelation;
using Helpers;
using CredentialRequesting;
using NBullet;

/// <summary>
/// Variant of <see cref="WabiSabiClient"/> that uses Bulletproofs++ for range proofs
/// instead of sigma-protocol bit decomposition. All other proofs (show credential,
/// balance, issuer parameter) remain as sigma protocols.
/// </summary>
public class BulletproofWabiSabiClient
{
	private readonly BulletproofPlusPlusRangeProof _rangeProofSystem;

	public BulletproofWabiSabiClient(
		CredentialIssuerParameters credentialIssuerParameters,
		BulletproofPlusPlusRangeProof rangeProofSystem,
		WasabiRandom randomNumberGenerator,
		int numberOfCredentials = ProtocolConstants.CredentialNumber)
	{
		if (numberOfCredentials < 1)
			throw new ArgumentOutOfRangeException(nameof(numberOfCredentials), "Must be at least 1.");
		NumberOfCredentials = numberOfCredentials;
		RandomNumberGenerator = Guard.NotNull(nameof(randomNumberGenerator), randomNumberGenerator);
		CredentialIssuerParameters = Guard.NotNull(nameof(credentialIssuerParameters), credentialIssuerParameters);
		_rangeProofSystem = rangeProofSystem;
	}

	public int NumberOfCredentials { get; }
	private CredentialIssuerParameters CredentialIssuerParameters { get; }
	private WasabiRandom RandomNumberGenerator { get; }

	public ZeroCredentialsRequestData CreateRequestForZeroAmount()
	{
		var credentialsToRequest = new IssuanceRequest[NumberOfCredentials];
		var knowledge = new Knowledge[NumberOfCredentials];
		var validationData = new IssuanceValidationData[NumberOfCredentials];

		for (var i = 0; i < NumberOfCredentials; i++)
		{
			var randomness = RandomNumberGenerator.GetScalar();
			var ma = randomness * Generators.Gh;

			knowledge[i] = ProofSystem.ZeroProofKnowledge(ma, randomness);
			credentialsToRequest[i] = new IssuanceRequest(ma, Enumerable.Empty<GroupElement>());
			validationData[i] = new IssuanceValidationData(0, randomness, ma);
		}

		var transcript = BuildTranscript(isNullRequest: true);

		return new(
			new ZeroCredentialsRequest(
				credentialsToRequest,
				ProofSystem.Prove(transcript, knowledge, RandomNumberGenerator)),
			new CredentialsResponseValidation(
				transcript,
				Enumerable.Empty<Credential>(),
				validationData));
	}

	public BulletproofRealCredentialsRequestData CreateRequest(
		IEnumerable<long> amountsToRequest,
		IEnumerable<Credential> credentialsToPresent,
		CancellationToken cancellationToken)
	{
		var credentialAmountsToRequest = amountsToRequest.ToList();
		var missingCredentialRequests = NumberOfCredentials - credentialAmountsToRequest.Count;
		for (var i = 0; i < missingCredentialRequests; i++)
			credentialAmountsToRequest.Add(0);

		return InternalCreateRequest(credentialAmountsToRequest, credentialsToPresent, cancellationToken);
	}

	public BulletproofRealCredentialsRequestData CreateRequest(
		IEnumerable<Credential> credentialsToPresent,
		CancellationToken cancellationToken)
	{
		return InternalCreateRequest(Array.Empty<long>(), credentialsToPresent, cancellationToken);
	}

	private BulletproofRealCredentialsRequestData InternalCreateRequest(
		IEnumerable<long> amountsToRequest,
		IEnumerable<Credential> credentialsToPresent,
		CancellationToken cancellationToken)
	{
		var credentialAmountsToRequest = amountsToRequest.ToList();

		var macsToPresent = credentialsToPresent.Select(x => x.Mac);
		if (macsToPresent.Distinct().Count() < macsToPresent.Count())
			throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.CredentialToPresentDuplicated);

		var zs = new List<Scalar>();
		var knowledgeToProve = new List<Knowledge>();
		var presentations = new List<CredentialPresentation>();
		foreach (var credential in credentialsToPresent)
		{
			var z = RandomNumberGenerator.GetScalar();
			var presentation = credential.Present(z);
			presentations.Add(presentation);
			knowledgeToProve.Add(ProofSystem.ShowCredentialKnowledge(presentation, z, credential, CredentialIssuerParameters));
			zs.Add(z);
		}

		// Generate BP++ range proofs for each requested credential (instead of sigma range proofs)
		var expectedNumberOfCredentials = credentialAmountsToRequest.Count;
		var credentialsToRequest = new IssuanceRequest[expectedNumberOfCredentials];
		var validationData = new IssuanceValidationData[expectedNumberOfCredentials];
		var bulletproofRangeProofs = new ReciprocalProof[expectedNumberOfCredentials];

		for (var i = 0; i < expectedNumberOfCredentials; i++)
		{
			var value = credentialAmountsToRequest[i];
			var scalar = new Scalar((ulong)value);
			var randomness = RandomNumberGenerator.GetScalar();
			var ma = ProofSystem.PedersenCommitment(scalar, randomness);

			// BP++ range proof instead of bit-decomposition sigma proof
			bulletproofRangeProofs[i] = _rangeProofSystem.Prove((ulong)value, randomness);

			// No bit commitments needed with BP++
			credentialsToRequest[i] = new IssuanceRequest(ma, Enumerable.Empty<GroupElement>());
			validationData[i] = new IssuanceValidationData(value, randomness, ma);
		}

		// Balance proof (same as original — sigma protocol)
		var sumOfZ = zs.Sum();
		var cr = credentialsToPresent.Select(x => x.Randomness).Sum();
		var r = validationData.Select(x => x.Randomness).Sum();
		var deltaR = cr + r.Negate();

		var balanceKnowledge = ProofSystem.BalanceProofKnowledge(sumOfZ, deltaR);
		knowledgeToProve.Add(balanceKnowledge);

		var transcript = BuildTranscript(isNullRequest: false);
		return new(
			new BulletproofRealCredentialsRequest(
				amountsToRequest.Sum() - credentialsToPresent.Sum(x => x.Value),
				presentations,
				credentialsToRequest,
				ProofSystem.Prove(transcript, knowledgeToProve, RandomNumberGenerator),
				bulletproofRangeProofs),
			new CredentialsResponseValidation(
				transcript,
				credentialsToPresent,
				validationData));
	}

	public IEnumerable<Credential> HandleResponse(
		CredentialsResponse registrationResponse,
		CredentialsResponseValidation registrationValidationData)
	{
		Guard.NotNull(nameof(registrationResponse), registrationResponse);
		Guard.NotNull(nameof(registrationValidationData), registrationValidationData);

		var issuedCredentialCount = registrationResponse.IssuedCredentials.Count();
		if (issuedCredentialCount != NumberOfCredentials)
			throw new WabiSabiCryptoException(
				WabiSabiCryptoErrorCode.IssuedCredentialNumberMismatch,
				$"{issuedCredentialCount} issued but {NumberOfCredentials} were requested.");

		var credentials = registrationValidationData.Requested.Zip(registrationResponse.IssuedCredentials)
			.Select(x => (Requested: x.First, Issued: x.Second))
			.ToArray();

		var statements = credentials
			.Select(x => ProofSystem.IssuerParametersStatement(CredentialIssuerParameters, x.Issued, x.Requested.Ma));

		var areCorrectlyIssued = ProofSystem.Verify(registrationValidationData.Transcript, statements, registrationResponse.Proofs);
		if (!areCorrectlyIssued)
			throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.ClientReceivedInvalidProofs);

		return credentials.Select(x => new Credential(x.Requested.Value, x.Requested.Randomness, x.Issued));
	}

	private Transcript BuildTranscript(bool isNullRequest)
	{
		var label = $"BulletproofUnifiedRegistration/{NumberOfCredentials}/{isNullRequest}";
		var encodedLabel = Encoding.UTF8.GetBytes(label);
		return new Transcript(encodedLabel);
	}
}

/// <summary>
/// Credential request carrying both sigma proofs (show credential + balance) and BP++ range proofs.
/// </summary>
public record BulletproofRealCredentialsRequest : ICredentialsRequest
{
	public BulletproofRealCredentialsRequest(
		long delta,
		IEnumerable<CredentialPresentation> presented,
		IEnumerable<IssuanceRequest> requested,
		IEnumerable<Proof> proofs,
		IEnumerable<ReciprocalProof> bulletproofRangeProofs)
	{
		Delta = delta;
		Presented = presented.ToImmutableValueSequence();
		Requested = requested.ToImmutableValueSequence();
		Proofs = proofs.ToImmutableValueSequence();
		BulletproofRangeProofs = bulletproofRangeProofs.ToArray();
	}

	public long Delta { get; }
	public ImmutableValueSequence<CredentialPresentation> Presented { get; }
	public ImmutableValueSequence<IssuanceRequest> Requested { get; }
	public ImmutableValueSequence<Proof> Proofs { get; }

	/// <summary>
	/// BP++ range proofs, one per requested credential.
	/// </summary>
	public ReciprocalProof[] BulletproofRangeProofs { get; }
}

/// <summary>
/// Pairs a BP++ credential request with its validation data.
/// </summary>
public record BulletproofRealCredentialsRequestData(
	BulletproofRealCredentialsRequest CredentialsRequest,
	CredentialsResponseValidation CredentialsResponseValidation);
