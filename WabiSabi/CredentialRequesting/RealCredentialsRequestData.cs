namespace WabiSabi.CredentialRequesting;

using Crypto;

public record RealCredentialsRequestData(
	RealCredentialsRequest CredentialsRequest,
	CredentialsResponseValidation CredentialsResponseValidation) : ICredentialRequestData
{
	ICredentialsRequest ICredentialRequestData.CredentialsRequest => CredentialsRequest;
}
