namespace WabiSabi;

public static class ProtocolConstants
{
	/// <summary>
	/// Default number of credentials presented and requested per registration.
	/// Can be overridden via constructor parameters on <see cref="Crypto.CredentialIssuer"/>
	/// and <see cref="Crypto.WabiSabiClient"/>.
	/// </summary>
	public const int CredentialNumber = 2;

	public const string WabiSabiProtocolIdentifier = "WabiSabi_v1.0";
	public const string DomainStrobeSeparator = "domain-separator";
}
