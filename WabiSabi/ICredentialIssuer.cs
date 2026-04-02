namespace WabiSabi.Crypto;

using CredentialRequesting;
using Randomness;

/// <summary>
/// Unified interface for WabiSabi credential issuers (classical sigma-protocol and BP++ variants).
/// </summary>
public interface ICredentialIssuer
{
	long MaxAmount { get; }
	long Balance { get; }
	int NumberOfCredentials { get; }
	CredentialIssuerSecretKey CredentialIssuerSecretKey { get; }

	CredentialsResponse HandleRequest(ICredentialsRequest registrationRequest);
	Task<CredentialsResponse> HandleRequestAsync(ICredentialsRequest registrationRequest, CancellationToken cancel);
}
