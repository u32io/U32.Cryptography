namespace U32.Cryptography;

/// <summary>
/// Configuration options for the <see cref="Konscious.Security.Cryptography.Argon2"/> hashing algorithm
/// </summary>
public sealed class Argon2Options
{
    private const int DefaultSaltLength = 16;
    private const int DefaultHashLength = 128;
    private const int DefaultDegreeOfParallelism = 2;
    private const int DefaultIterations = 40;
    private const int DefaultMemorySize = 8192;

    public int SaltLength { get; set; } = DefaultSaltLength;
    public int HashLength { get; set; } = DefaultHashLength;
    public int DegreeOfParallelism { get; set; } = DefaultDegreeOfParallelism;
    public int Iterations { get; set; } = DefaultIterations;
    public int MemorySize { get; set; } = DefaultMemorySize;

    public static Argon2Options Default => new();
}