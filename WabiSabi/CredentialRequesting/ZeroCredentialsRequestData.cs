namespace WabiSabi.CredentialRequesting;

using Crypto;

public record ZeroCredentialsRequestData(
	ZeroCredentialsRequest CredentialsRequest,
	CredentialsResponseValidation CredentialsResponseValidation) : ICredentialRequestData
{
	ICredentialsRequest ICredentialRequestData.CredentialsRequest => CredentialsRequest;
}
