namespace WabiSabi.Crypto;

using CredentialRequesting;
using ZeroKnowledge;

/// <summary>
/// Common interface for credential request data, allowing both classical and BP++ variants
/// to be used interchangeably by the round client.
/// </summary>
public interface ICredentialRequestData
{
	ICredentialsRequest CredentialsRequest { get; }
	CredentialsResponseValidation CredentialsResponseValidation { get; }
}

/// <summary>
/// Unified interface for WabiSabi credential clients (classical sigma-protocol and BP++ variants).
/// </summary>
public interface ICredentialClient
{
	int NumberOfCredentials { get; }

	ICredentialRequestData CreateRequestForZeroAmount();

	ICredentialRequestData CreateRequest(
		IEnumerable<long> amountsToRequest,
		IEnumerable<Credential> credentialsToPresent,
		CancellationToken cancellationToken);

	ICredentialRequestData CreateRequest(
		IEnumerable<Credential> credentialsToPresent,
		CancellationToken cancellationToken);

	IEnumerable<Credential> HandleResponse(
		CredentialsResponse registrationResponse,
		CredentialsResponseValidation registrationValidationData);
}
