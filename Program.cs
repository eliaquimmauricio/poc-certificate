using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

static bool CheckIfContainsOnlyLettersAndDigits(string input)
{
    return input.All(char.IsLetterOrDigit);
}

static X509Certificate2 ReadCertificateFromPath(string certificatePath, string privateKeyPath, string passwordPrivateKey = "")
{
    string privateKeyContent = string.Join(null, File.ReadAllLines(privateKeyPath, System.Text.Encoding.UTF8).Where(x => !x.StartsWith("-")));

    byte[] binaryEnconding = Convert.FromBase64String(privateKeyContent);

    using RSA rsa = RSA.Create();

    try
    {
        rsa.ImportEncryptedPkcs8PrivateKey(passwordPrivateKey, binaryEnconding, out _);
    }
    catch (Exception)
    {
        rsa.ImportPkcs8PrivateKey(binaryEnconding, out _);
    }

    using X509Certificate2 pubOnly = new(certificatePath);
    using X509Certificate2 pubPrivEphemeral = pubOnly.CopyWithPrivateKey(rsa);
    return new X509Certificate2(pubPrivEphemeral.Export(X509ContentType.Pfx));
}

static X509Certificate2? ReadCertificateFromStore(string serialNumber)
{
    using X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

    try
    {
        store.Open(OpenFlags.ReadOnly | OpenFlags.IncludeArchived);

        X509Certificate2Collection certCollection = store.Certificates;

        return certCollection.OfType<X509Certificate2>().Where(cert => cert.SerialNumber.Contains(serialNumber, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
    }
    finally
    {
        store.Close();
    }
}

/* Utilizaremos as configurações já existentes hoje, logo, primeiro iremos checar se encontramos pelo serial number (método correto), 

 senão iremos tentar pelo caminho do certificado como já é feito hoje. */

string certificateOrigin = "2e00000026fef35ce84f269e6d000000000026";

X509Certificate2? certificate = null;

if (CheckIfContainsOnlyLettersAndDigits(certificateOrigin))
    certificate = ReadCertificateFromStore(certificateOrigin);
else
    certificate = ReadCertificateFromPath(certificateOrigin, "C:/Teste/PrivateKeyPath.key");

if (certificate is null)
    throw new ArgumentException("O certificado não foi encontrado!");

Console.ReadKey();